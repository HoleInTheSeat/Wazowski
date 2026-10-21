//! RDP backend built on `ironrdp`.
//!
//! Runs on a current-thread Tokio runtime: connects (TCP → TLS via rustls+ring →
//! CredSSP/NLA), then drives an `ActiveStage`, publishing the decoded RGBA image
//! to the shared [`FrameBuf`] and forwarding mouse/keyboard input. Mirrors the
//! shape of the VNC backend so the UI side is identical.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ironrdp::connector::{
    ClientConnector, Config, Credentials, DesktopSize, ServerName,
};
use ironrdp::pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp::pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStageBuilder, ActiveStageOutput};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::{FrameBuf, RemoteEvent, RemoteInput};

/// Parameters for an RDP connection.
pub struct RdpParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub domain: String,
    pub width: u16,
    pub height: u16,
    pub view_only: bool,
    pub quality: crate::RdpQuality,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    params: RdpParams,
    frame: Arc<Mutex<FrameBuf>>,
    ev_tx: std::sync::mpsc::Sender<RemoteEvent>,
    mut in_rx: UnboundedReceiver<RemoteInput>,
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
) {
    if let Err(e) = run_inner(&params, &frame, &ev_tx, &mut in_rx, &shutdown, &active).await {
        let _ = ev_tx.send(RemoteEvent::Error(e.to_string()));
    }
    let _ = ev_tx.send(RemoteEvent::Disconnected);
}

/// A `NetworkClient` is only used for Kerberos (KDC round-trips). We authenticate
/// with NTLM/password and pass no Kerberos config, so this is never invoked.
struct NoNetwork;

impl ironrdp_tokio::NetworkClient for NoNetwork {
    #[allow(clippy::manual_async_fn)]
    fn send(
        &mut self,
        _request: &ironrdp::connector::sspi::generator::NetworkRequest,
    ) -> impl std::future::Future<Output = ironrdp::connector::ConnectorResult<Vec<u8>>> {
        async { unreachable!("Kerberos network client is not used with password authentication") }
    }
}

fn build_config(params: &RdpParams) -> anyhow::Result<Config> {
    use ironrdp::pdu::gcc::KeyboardType;
    use ironrdp::pdu::rdp::capability_sets::{MajorPlatformType, client_codecs_capabilities};
    use ironrdp::pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};

    let codecs = client_codecs_capabilities(&[]).map_err(|help| anyhow::anyhow!("{help}"))?;
    let (width, height) =
        if params.width == 0 || params.height == 0 { (1280, 800) } else { (params.width, params.height) };

    // Quality → color depth + server performance flags (disabling eye-candy the
    // server would otherwise render and stream, which is the biggest bandwidth win).
    let (color_depth, performance_flags) = match params.quality {
        crate::RdpQuality::Performance => (
            16,
            PerformanceFlags::DISABLE_WALLPAPER
                | PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS
                | PerformanceFlags::DISABLE_THEMING
                | PerformanceFlags::DISABLE_CURSOR_SHADOW
                | PerformanceFlags::DISABLE_CURSORSETTINGS,
        ),
        crate::RdpQuality::Balanced => (
            32,
            PerformanceFlags::DISABLE_WALLPAPER
                | PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS,
        ),
        crate::RdpQuality::Quality => (
            32,
            PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS
                | PerformanceFlags::ENABLE_FONT_SMOOTHING,
        ),
    };

    Ok(Config {
        desktop_size: DesktopSize { width, height },
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: true,
        credentials: Credentials::UsernamePassword {
            username: params.username.clone(),
            password: params.password.clone(),
        },
        domain: (!params.domain.is_empty()).then(|| params.domain.clone()),
        client_build: 0,
        client_name: "Wazowski".to_owned(),
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),
        bitmap: Some(ironrdp::connector::BitmapConfig {
            color_depth,
            lossy_compression: true,
            codecs,
        }),
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        performance_flags,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: Some(CompressionType::K64),
        enable_server_pointer: true,
        pointer_software_rendering: true,
        multitransport_flags: None,
    })
}

async fn run_inner(
    params: &RdpParams,
    frame: &Arc<Mutex<FrameBuf>>,
    ev_tx: &std::sync::mpsc::Sender<RemoteEvent>,
    in_rx: &mut UnboundedReceiver<RemoteInput>,
    shutdown: &Arc<AtomicBool>,
    visible: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    // Install the rustls ring provider once (shared with the VNC backend; the
    // second caller just gets an Err we ignore).
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let tcp = tokio::net::TcpStream::connect((params.host.as_str(), params.port)).await?;
    let client_addr = tcp.local_addr()?;
    let mut framed = ironrdp_tokio::TokioFramed::new(tcp);

    let config = build_config(params)?;
    let mut connector = ClientConnector::new(config, client_addr);

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| anyhow::anyhow!("RDP connect: {e}"))?;
    let (initial, leftover) = framed.into_inner();
    let (tls, cert) = ironrdp_tls::upgrade(initial, &params.host)
        .await
        .map_err(|e| anyhow::anyhow!("RDP TLS: {e}"))?;
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&cert)
        .ok_or_else(|| anyhow::anyhow!("RDP: could not read the server's TLS public key"))?
        .to_owned();
    let mut upgraded_framed = ironrdp_tokio::TokioFramed::new_with_leftover(tls, leftover);

    let result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut NoNetwork,
        ServerName::new(&params.host),
        server_public_key,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("RDP auth/finalize: {e}"))?;

    let desktop = result.desktop_size;
    let _ = ev_tx.send(RemoteEvent::Resized(desktop.width, desktop.height));
    let mut image = DecodedImage::new(
        ironrdp::graphics::image_processing::PixelFormat::RgbA32,
        desktop.width,
        desktop.height,
    );
    let mut active = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();

    let mut keyboard = Keyboard::default();
    let mut mouse_buttons = 0u8;

    // Graphics updates are coalesced: each one just marks the image dirty, and a
    // timer publishes the latest frame at ~60 Hz. Cloning the whole framebuffer on
    // every PDU (there can be hundreds per second while text scrolls) was the main
    // cause of input lag — this caps it to one clone per displayed frame.
    let mut dirty = false;
    let mut publish_timer = tokio::time::interval(Duration::from_millis(16));
    publish_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    'session: loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let outputs = tokio::select! {
            _ = publish_timer.tick() => {
                // Only copy the framebuffer to the UI while the tab is visible —
                // the server keeps pushing (RDP is server-driven), but there's no
                // point spending the per-frame copy on a tab nobody is watching.
                if dirty && visible.load(Ordering::Relaxed) {
                    publish(frame, &image);
                    dirty = false;
                }
                Vec::new()
            }
            input = in_rx.recv() => {
                let Some(input) = input else { break };
                if params.view_only {
                    Vec::new()
                } else {
                    let events = translate_input(input, &mut keyboard, &mut mouse_buttons);
                    if events.is_empty() {
                        Vec::new()
                    } else {
                        active.process_fastpath_input(&mut image, &events)
                            .map_err(|e| anyhow::anyhow!("RDP input: {e}"))?
                    }
                }
            }
            pdu = upgraded_framed.read_pdu() => {
                let (action, payload) = pdu.map_err(|e| anyhow::anyhow!("RDP read: {e}"))?;
                active.process(&mut image, action, &payload)
                    .map_err(|e| anyhow::anyhow!("RDP process: {e}"))?
            }
        };

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(response) => {
                    use ironrdp_tokio::FramedWrite;
                    upgraded_framed
                        .write_all(&response)
                        .await
                        .map_err(|e| anyhow::anyhow!("RDP write: {e}"))?;
                }
                ActiveStageOutput::GraphicsUpdate(_) => dirty = true,
                ActiveStageOutput::Terminate(_) => break 'session,
                ActiveStageOutput::DeactivateAll => {
                    anyhow::bail!("the RDP server re-initialized the session (resolution change?) — reconnect")
                }
                // Cursor shapes/positions: the server renders the pointer into the
                // framebuffer for us (pointer_software_rendering), so ignore these.
                _ => {}
            }
        }
    }

    Ok(())
}

/// Copies the decoded image (RGBA) into the shared framebuffer.
fn publish(frame: &Arc<Mutex<FrameBuf>>, image: &DecodedImage) {
    let (w, h) = (image.width() as usize, image.height() as usize);
    if w == 0 {
        return;
    }
    if let Ok(mut guard) = frame.lock() {
        guard.width = w;
        guard.height = h;
        guard.rgba.clear();
        guard.rgba.extend_from_slice(image.data());
        guard.seq = guard.seq.wrapping_add(1);
    }
}

/// Tracks modifier state so Ctrl/Alt combos use scancodes (not Unicode).
#[derive(Default)]
struct Keyboard {
    ctrl: bool,
    alt: bool,
}

/// Converts a UI input event into RDP fast-path events.
fn translate_input(
    input: RemoteInput,
    kb: &mut Keyboard,
    mouse_buttons: &mut u8,
) -> Vec<FastPathInputEvent> {
    match input {
        RemoteInput::Pointer { x, y, buttons } => mouse_events(x, y, buttons, mouse_buttons),
        RemoteInput::Key { keysym, down } => key_events(keysym, down, kb),
    }
}

fn mouse_events(x: u16, y: u16, buttons: u8, prev: &mut u8) -> Vec<FastPathInputEvent> {
    let mut out = Vec::new();
    let mk = |flags: PointerFlags, wheel: i16| {
        FastPathInputEvent::MouseEvent(MousePdu {
            flags,
            number_of_wheel_rotation_units: wheel,
            x_position: x,
            y_position: y,
        })
    };
    out.push(mk(PointerFlags::MOVE, 0));

    for (bit, flag) in [
        (0u8, PointerFlags::LEFT_BUTTON),
        (1, PointerFlags::MIDDLE_BUTTON_OR_WHEEL),
        (2, PointerFlags::RIGHT_BUTTON),
    ] {
        let now = buttons & (1 << bit) != 0;
        let was = *prev & (1 << bit) != 0;
        if now != was {
            let flags = if now { flag | PointerFlags::DOWN } else { flag };
            out.push(mk(flags, 0));
        }
    }
    *prev = buttons & 0b0000_0111;

    // Wheel bits (3 = up, 4 = down) are momentary; emit a rotation for each.
    if buttons & 0b0000_1000 != 0 {
        out.push(mk(PointerFlags::VERTICAL_WHEEL, 120));
    }
    if buttons & 0b0001_0000 != 0 {
        out.push(mk(PointerFlags::VERTICAL_WHEEL | PointerFlags::WHEEL_NEGATIVE, -120));
    }
    out
}

fn key_events(keysym: u32, down: bool, kb: &mut Keyboard) -> Vec<FastPathInputEvent> {
    // Track Ctrl/Alt so letter/digit combos use scancodes rather than Unicode.
    match keysym {
        0xffe3 => kb.ctrl = down,
        0xffe9 => kb.alt = down,
        _ => {}
    }
    let mut flags = KeyboardFlags::empty();
    if !down {
        flags |= KeyboardFlags::RELEASE;
    }

    if let Some((code, extended)) = special_scancode(keysym) {
        if extended {
            flags |= KeyboardFlags::EXTENDED;
        }
        return vec![FastPathInputEvent::KeyboardEvent(flags, code)];
    }
    // Printable key: send a scancode under Ctrl/Alt (so combos work), otherwise
    // send the character directly as Unicode (handles layout/shift correctly).
    if (kb.ctrl || kb.alt)
        && let Some(code) = letter_digit_scancode(keysym)
    {
        return vec![FastPathInputEvent::KeyboardEvent(flags, code)];
    }
    // X11 Unicode keysyms are `0x0100_0000 + codepoint`; plain ASCII keysyms are
    // the codepoint itself. Reduce to the raw codepoint for the Unicode event.
    let codepoint = if keysym & 0xff00_0000 == 0x0100_0000 { keysym & 0x00ff_ffff } else { keysym };
    if let Ok(ch) = u16::try_from(codepoint) {
        return vec![FastPathInputEvent::UnicodeKeyboardEvent(flags, ch)];
    }
    Vec::new()
}

/// Set-1 scancode (and whether it's an E0-extended key) for special keysyms,
/// modifiers, and function keys.
fn special_scancode(keysym: u32) -> Option<(u8, bool)> {
    Some(match keysym {
        0xff0d => (0x1C, false), // Enter
        0xff1b => (0x01, false), // Escape
        0xff08 => (0x0E, false), // Backspace
        0xff09 => (0x0F, false), // Tab
        0x20 => (0x39, false),   // Space (needed for Ctrl+Space)
        0xffff => (0x53, true),  // Delete
        0xff63 => (0x52, true),  // Insert
        0xff50 => (0x47, true),  // Home
        0xff57 => (0x4F, true),  // End
        0xff55 => (0x49, true),  // Page Up
        0xff56 => (0x51, true),  // Page Down
        0xff51 => (0x4B, true),  // Left
        0xff52 => (0x48, true),  // Up
        0xff53 => (0x4D, true),  // Right
        0xff54 => (0x50, true),  // Down
        0xffe1 => (0x2A, false), // Shift
        0xffe3 => (0x1D, false), // Ctrl
        0xffe9 => (0x38, false), // Alt
        0xffeb => (0x5B, true),  // Super / Windows (left)
        0xffbe => (0x3B, false), // F1
        0xffbf => (0x3C, false),
        0xffc0 => (0x3D, false),
        0xffc1 => (0x3E, false),
        0xffc2 => (0x3F, false),
        0xffc3 => (0x40, false),
        0xffc4 => (0x41, false),
        0xffc5 => (0x42, false),
        0xffc6 => (0x43, false),
        0xffc7 => (0x44, false),
        0xffc8 => (0x57, false), // F11
        0xffc9 => (0x58, false), // F12
        _ => return None,
    })
}

/// Set-1 scancode for a letter/digit keysym (US layout), for Ctrl/Alt combos.
fn letter_digit_scancode(keysym: u32) -> Option<u8> {
    let ch = char::from_u32(keysym)?.to_ascii_lowercase();
    Some(match ch {
        'a' => 0x1E, 'b' => 0x30, 'c' => 0x2E, 'd' => 0x20, 'e' => 0x12, 'f' => 0x21,
        'g' => 0x22, 'h' => 0x23, 'i' => 0x17, 'j' => 0x24, 'k' => 0x25, 'l' => 0x26,
        'm' => 0x32, 'n' => 0x31, 'o' => 0x18, 'p' => 0x19, 'q' => 0x10, 'r' => 0x13,
        's' => 0x1F, 't' => 0x14, 'u' => 0x16, 'v' => 0x2F, 'w' => 0x11, 'x' => 0x2D,
        'y' => 0x15, 'z' => 0x2C,
        '1' => 0x02, '2' => 0x03, '3' => 0x04, '4' => 0x05, '5' => 0x06, '6' => 0x07,
        '7' => 0x08, '8' => 0x09, '9' => 0x0A, '0' => 0x0B,
        _ => return None,
    })
}
