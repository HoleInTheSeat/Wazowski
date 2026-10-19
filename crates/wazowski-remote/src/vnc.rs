//! VNC (RFB) backend built on `vnc-rs`.
//!
//! Runs on a current-thread Tokio runtime: polls protocol events into a local
//! RGBA framebuffer, publishes it to the shared [`FrameBuf`] when a batch changes,
//! and forwards queued input. We request an RGBA pixel format (so image data
//! lands in egui's byte order) and avoid Tight/Cursor encodings to keep decoding
//! to the server-rendered framebuffer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedReceiver;
use vnc::client::auth::{AuthHelper, AuthResult};
use vnc::{PixelFormat, Rect, VncClient, VncEncoding, VncEvent, X11Event};

use crate::{FrameBuf, RemoteEvent, RemoteInput, RemoteOptions, VncQuality};

/// A local framebuffer the protocol events paint into before publishing.
#[derive(Default)]
struct Local {
    w: usize,
    h: usize,
    rgba: Vec<u8>,
}

impl Local {
    fn resize(&mut self, w: usize, h: usize) {
        self.w = w;
        self.h = h;
        self.rgba = vec![0; w * h * 4];
        for px in self.rgba.as_chunks_mut::<4>().0 {
            px[3] = 255;
        }
    }

    /// Blits `data` (RGBA) into the rectangle, clamped to the framebuffer.
    fn blit(&mut self, rect: Rect, data: &[u8]) {
        let (fx, fy) = (rect.x as usize, rect.y as usize);
        let (rw, rh) = (rect.width as usize, rect.height as usize);
        if self.w == 0 || data.len() < rw * rh * 4 {
            return;
        }
        for row in 0..rh {
            let dy = fy + row;
            if dy >= self.h {
                break;
            }
            let copy_w = rw.min(self.w.saturating_sub(fx));
            if copy_w == 0 {
                continue;
            }
            let src = (row * rw) * 4;
            let dst = (dy * self.w + fx) * 4;
            self.rgba[dst..dst + copy_w * 4].copy_from_slice(&data[src..src + copy_w * 4]);
        }
    }

    /// Copies a rectangle from `src` to `dst` within the framebuffer.
    fn copy(&mut self, dst: Rect, src: Rect) {
        let (rw, rh) = (src.width as usize, src.height as usize);
        if self.w == 0 {
            return;
        }
        // Snapshot the source region first to stay correct when regions overlap.
        let mut buf = vec![0u8; rw * rh * 4];
        for row in 0..rh {
            let sy = src.y as usize + row;
            if sy >= self.h {
                break;
            }
            let copy_w = rw.min(self.w.saturating_sub(src.x as usize));
            if copy_w == 0 {
                continue;
            }
            let s = (sy * self.w + src.x as usize) * 4;
            buf[row * rw * 4..row * rw * 4 + copy_w * 4].copy_from_slice(&self.rgba[s..s + copy_w * 4]);
        }
        self.blit(Rect { x: dst.x, y: dst.y, width: src.width, height: src.height }, &buf);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    host: String,
    port: u16,
    password: Option<String>,
    options: RemoteOptions,
    frame: Arc<Mutex<FrameBuf>>,
    ev_tx: std::sync::mpsc::Sender<RemoteEvent>,
    mut in_rx: UnboundedReceiver<RemoteInput>,
    shutdown: Arc<AtomicBool>,
) {
    if let Err(e) =
        run_inner(&host, port, password, &options, &frame, &ev_tx, &mut in_rx, &shutdown).await
    {
        let _ = ev_tx.send(RemoteEvent::Error(friendly_error(&e.to_string())));
    }
    let _ = ev_tx.send(RemoteEvent::Disconnected);
}

/// Rewrites known low-level errors into something the user can act on.
fn friendly_error(msg: &str) -> String {
    msg.to_owned()
}

#[allow(clippy::too_many_arguments)]
async fn run_inner(
    host: &str,
    port: u16,
    password: Option<String>,
    options: &RemoteOptions,
    frame: &Arc<Mutex<FrameBuf>>,
    ev_tx: &std::sync::mpsc::Sender<RemoteEvent>,
    in_rx: &mut UnboundedReceiver<RemoteInput>,
    shutdown: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let client = connect(host, port, password.unwrap_or_default(), options).await?;

    let mut local = Local::default();
    let mut refresh = Instant::now();
    let _ = client.input(X11Event::Refresh).await;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Forward all queued input (dropped when observing only).
        while let Ok(input) = in_rx.try_recv() {
            if options.view_only {
                continue;
            }
            let x11 = match input {
                RemoteInput::Pointer { x, y, buttons } => {
                    X11Event::PointerEvent((x, y, buttons).into())
                }
                RemoteInput::Key { keysym, down } => X11Event::KeyEvent((keysym, down).into()),
            };
            let _ = client.input(x11).await;
        }

        // Drain all currently-available protocol events into the local buffer.
        let mut dirty = false;
        loop {
            match client.poll_event().await {
                Ok(Some(ev)) => dirty |= apply(ev, &mut local, ev_tx),
                Ok(None) => break,
                Err(e) => return Err(anyhow::anyhow!(e.to_string())),
            }
        }

        // Publish a fresh frame to the UI only when something changed.
        if dirty
            && local.w > 0
            && let Ok(mut guard) = frame.lock()
        {
            guard.width = local.w;
            guard.height = local.h;
            guard.rgba.clear();
            guard.rgba.extend_from_slice(&local.rgba);
            guard.seq = guard.seq.wrapping_add(1);
        }

        if refresh.elapsed() >= Duration::from_millis(33) {
            let _ = client.input(X11Event::Refresh).await;
            refresh = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let _ = client.close().await;
    Ok(())
}

/// Applies one event to the local framebuffer; returns whether pixels changed.
fn apply(ev: VncEvent, local: &mut Local, ev_tx: &std::sync::mpsc::Sender<RemoteEvent>) -> bool {
    match ev {
        VncEvent::SetResolution(screen) => {
            local.resize(screen.width as usize, screen.height as usize);
            let _ = ev_tx.send(RemoteEvent::Resized(screen.width, screen.height));
            true
        }
        VncEvent::DesktopUpdate(update) => {
            if let Some(layout) = update.layout {
                local.resize(layout.width as usize, layout.height as usize);
                let _ = ev_tx.send(RemoteEvent::Resized(layout.width, layout.height));
                return true;
            }
            false
        }
        VncEvent::RawImage(rect, data) => {
            local.blit(rect, &data);
            true
        }
        VncEvent::Copy(dst, src) => {
            local.copy(dst, src);
            true
        }
        // Encodings we don't opt into, plus notifications we ignore.
        VncEvent::JpegImage(..)
        | VncEvent::SetCursor(..)
        | VncEvent::SetPixelFormat(_)
        | VncEvent::Bell
        | VncEvent::Text(_) => false,
        VncEvent::Error(e) => {
            let _ = ev_tx.send(RemoteEvent::Error(e));
            false
        }
        // `VncEvent` is `#[non_exhaustive]`; ignore anything new.
        _ => false,
    }
}

/// Performs the RFB handshake ourselves (ProtocolVersion → security →, for
/// VeNCrypt, TLS + sub-auth → VNC authentication), then hands the authenticated
/// stream to `vnc-rs`'s post-init engine. Supports plain `None`/`VncAuth` and
/// VeNCrypt with an X509 (server-cert) sub-type — the only one rustls can do,
/// since VeNCrypt's `TLSxxx`/`TLS(18)` sub-types use anonymous TLS.
async fn connect(
    host: &str,
    port: u16,
    password: String,
    options: &RemoteOptions,
) -> anyhow::Result<VncClient> {
    let mut tcp = TcpStream::connect((host, port)).await?;

    // ProtocolVersion: read the server's, reply with ours (cap at 3.8).
    let mut ver = [0u8; 12];
    tcp.read_exact(&mut ver).await?;
    let minor = parse_rfb_minor(&ver);
    tcp.write_all(b"RFB 003.008\n").await?;

    // Security types. RFB 3.3 uses a single u32 chosen by the server; 3.7+ sends
    // a list the client chooses from.
    let pf = Some(PixelFormat::rgba());
    let encs = encodings(options.quality);
    if minor < 7 {
        let chosen = tcp.read_u32().await?;
        match chosen {
            1 => {} // None, no SecurityResult in 3.3
            2 => vnc_auth(&mut tcp, &password).await?,
            other => anyhow::bail!("unsupported VNC security type {other} (RFB 3.3)"),
        }
        return Ok(VncClient::new(tcp, options.shared, pf, encs).await?);
    }

    let count = tcp.read_u8().await?;
    if count == 0 {
        anyhow::bail!("server rejected the connection: {}", read_reason(&mut tcp).await);
    }
    let mut types = vec![0u8; count as usize];
    tcp.read_exact(&mut types).await?;

    // Prefer VeNCrypt (richer servers, e.g. the copier) → VncAuth → None.
    if types.contains(&19) {
        let tls = vencrypt_upgrade(tcp, host, &password).await?;
        return Ok(VncClient::new(tls, options.shared, pf, encs).await?);
    }
    if types.contains(&2) {
        tcp.write_u8(2).await?;
        vnc_auth(&mut tcp, &password).await?;
        return Ok(VncClient::new(tcp, options.shared, pf, encs).await?);
    }
    if types.contains(&1) {
        tcp.write_u8(1).await?;
        read_security_result(&mut tcp).await?; // RFB 3.8 sends a result even for None
        return Ok(VncClient::new(tcp, options.shared, pf, encs).await?);
    }
    anyhow::bail!(
        "this VNC server offers no security type Wazowski supports (got {types:?}); \
         only None, VNC Authentication, and VeNCrypt-X509 are implemented"
    )
}

/// Minor version from an "RFB 003.00N" greeting (defaults to 8 if unparseable).
fn parse_rfb_minor(ver: &[u8; 12]) -> u8 {
    std::str::from_utf8(&ver[8..11]).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(8)
}

/// Reads a length-prefixed failure reason string (best-effort).
async fn read_reason<S: AsyncReadExt + Unpin>(stream: &mut S) -> String {
    let Ok(len) = stream.read_u32().await else { return "unknown".into() };
    let mut buf = vec![0u8; (len as usize).min(1024)];
    if stream.read_exact(&mut buf).await.is_err() {
        return "unknown".into();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Standard VNC Authentication (DES challenge/response), reusing vnc-rs's helper.
/// Consumes the trailing SecurityResult word.
async fn vnc_auth<S>(stream: &mut S, password: &str) -> anyhow::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let auth = AuthHelper::read(stream, password).await?;
    auth.write(stream).await?;
    match auth.finish(stream).await? {
        AuthResult::Ok => Ok(()),
        AuthResult::Failed => anyhow::bail!("VNC authentication failed (wrong password?)"),
    }
}

/// Reads an RFB 3.8 SecurityResult (0 = ok), with the failure reason on error.
async fn read_security_result<S>(stream: &mut S) -> anyhow::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    if stream.read_u32().await? == 0 {
        Ok(())
    } else {
        anyhow::bail!("VNC security negotiation failed: {}", read_reason(stream).await)
    }
}

/// VeNCrypt sub-handshake: negotiate version 0.2, pick an X509 sub-type (server
/// certificate; anonymous-TLS sub-types can't be done with rustls), perform the
/// TLS handshake (certificate not verified, like every RDP/VNC client), then run
/// the sub-type's VNC authentication inside the tunnel.
async fn vencrypt_upgrade(
    mut tcp: TcpStream,
    host: &str,
    password: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    tcp.write_u8(19).await?; // select VeNCrypt

    // Version negotiation.
    let mut sv = [0u8; 2];
    tcp.read_exact(&mut sv).await?;
    tcp.write_all(&[0, 2]).await?;
    if tcp.read_u8().await? != 0 {
        anyhow::bail!("VeNCrypt version 0.2 was rejected by the server");
    }

    // Sub-type list.
    let nsub = tcp.read_u8().await?;
    if nsub == 0 {
        anyhow::bail!("VeNCrypt offered no sub-types: {}", read_reason(&mut tcp).await);
    }
    let mut raw = vec![0u8; nsub as usize * 4];
    tcp.read_exact(&mut raw).await?;
    let subtypes: Vec<u32> =
        raw.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes(*c)).collect();

    // 261 = X509Vnc, 260 = X509None (both use a real server certificate).
    const X509_VNC: u32 = 261;
    const X509_NONE: u32 = 260;
    let chosen = if subtypes.contains(&X509_VNC) {
        X509_VNC
    } else if subtypes.contains(&X509_NONE) {
        X509_NONE
    } else {
        anyhow::bail!(
            "this VeNCrypt server only offers anonymous-TLS sub-types ({subtypes:?}); \
             Wazowski needs an X509 (server-certificate) sub-type"
        )
    };
    tcp.write_all(&chosen.to_be_bytes()).await?;

    // The TLS/X509 sub-security sends a one-byte "continue" flag before the TLS
    // handshake (1 = proceed, 0 = failure + reason). Missing this byte makes the
    // TLS layer read it as a record and fail with "InvalidContentType".
    if tcp.read_u8().await? == 0 {
        anyhow::bail!("VeNCrypt sub-type was refused: {}", read_reason(&mut tcp).await);
    }

    let mut tls = tls_handshake(tcp, host).await?;
    match chosen {
        X509_VNC => vnc_auth(&mut tls, password).await?,
        X509_NONE => read_security_result(&mut tls).await?,
        _ => unreachable!(),
    }
    Ok(tls)
}

/// TLS client handshake with certificate verification disabled (RDP/VNC servers
/// typically present self-signed certs). Uses rustls with the ring provider.
async fn tls_handshake(
    tcp: TcpStream,
    host: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    use tokio_rustls::rustls;
    // Install the ring crypto provider once (ignored if already set).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .unwrap_or(rustls::pki_types::ServerName::IpAddress(
            std::net::Ipv4Addr::LOCALHOST.into(),
        ));
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    Ok(connector.connect(server_name, tcp).await?)
}

/// Accept any server certificate (TLS is used only as a transport here).
#[derive(Debug)]
struct NoVerify;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        use tokio_rustls::rustls::SignatureScheme as S;
        vec![
            S::RSA_PKCS1_SHA1,
            S::ECDSA_SHA1_Legacy,
            S::RSA_PKCS1_SHA256,
            S::ECDSA_NISTP256_SHA256,
            S::RSA_PKCS1_SHA384,
            S::ECDSA_NISTP384_SHA384,
            S::RSA_PKCS1_SHA512,
            S::ECDSA_NISTP521_SHA512,
            S::RSA_PSS_SHA256,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA512,
            S::ED25519,
            S::ED448,
        ]
    }
}

fn encodings(quality: VncQuality) -> Vec<VncEncoding> {
    // Raw is required by the RFC; DesktopSizePseudo lets the server resize us.
    match quality {
        VncQuality::Auto | VncQuality::Low => vec![
            VncEncoding::Zrle,
            VncEncoding::CopyRect,
            VncEncoding::DesktopSizePseudo,
            VncEncoding::Raw,
        ],
        VncQuality::High => vec![
            VncEncoding::CopyRect,
            VncEncoding::DesktopSizePseudo,
            VncEncoding::Raw,
            VncEncoding::Zrle,
        ],
    }
}
