//! In-app updates: check GitHub Releases and self-replace the binary/AppImage.
//!
//! The update mechanism depends on how the app was installed:
//! - an **AppImage** replaces its own `.AppImage` file (via `$APPIMAGE`),
//! - a standalone **executable** (the Windows per-user install, a raw binary)
//!   self-replaces the running exe,
//! - a **package-manager** install (dnf/apt, under a system prefix) is left
//!   alone — the user updates it with their package manager.
//!
//! Network/IO runs on a worker thread; the UI polls a shared cell.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const REPO: &str = "HoleInTheSeat/Wazowski";
const USER_AGENT: &str = concat!("Wazowski/", env!("CARGO_PKG_VERSION"));

/// This build's version (from Cargo).
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// A GitHub release, trimmed to what the updater needs.
#[derive(Clone)]
pub struct Release {
    /// Version without the leading `v` (e.g. `2.0.6`).
    pub version: String,
    pub notes: String,
    pub url: String,
    assets: Vec<Asset>,
}

#[derive(Clone, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct ReleaseJson {
    tag_name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

/// How this build was installed — decides whether and how it can self-update.
#[derive(Clone, Debug)]
pub enum InstallKind {
    /// Replace this `.AppImage` file in place.
    AppImage(PathBuf),
    /// Replace this standalone executable (Windows exe, raw binary).
    Executable(PathBuf),
    /// Owned by a package manager (dnf/apt/…): update out-of-band.
    Managed,
}

impl InstallKind {
    /// Whether this install can update itself.
    pub fn can_self_update(&self) -> bool {
        !matches!(self, InstallKind::Managed)
    }

    /// The file to relaunch after an update.
    fn launch_target(&self) -> Option<PathBuf> {
        match self {
            InstallKind::AppImage(p) | InstallKind::Executable(p) => Some(p.clone()),
            InstallKind::Managed => std::env::current_exe().ok(),
        }
    }
}

/// Detects how this build was installed.
pub fn install_kind() -> InstallKind {
    // An AppImage exposes its own path via $APPIMAGE (the mounted binary's
    // current_exe() points inside the mount, not at the .AppImage file).
    if let Ok(appimage) = std::env::var("APPIMAGE")
        && !appimage.is_empty()
    {
        return InstallKind::AppImage(PathBuf::from(appimage));
    }
    let Ok(exe) = std::env::current_exe() else {
        return InstallKind::Managed;
    };
    #[cfg(target_os = "linux")]
    {
        // A packaged install lives under a system prefix we must not overwrite.
        let p = exe.to_string_lossy();
        let system = p.starts_with("/usr/") || p.starts_with("/opt/") || p.starts_with("/bin/");
        if system || !is_writable(&exe) {
            return InstallKind::Managed;
        }
    }
    InstallKind::Executable(exe)
}

#[cfg(target_os = "linux")]
fn is_writable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // Writable by the owner, and we own it (best-effort; a failed update just
    // surfaces an error later).
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o200 != 0)
        .unwrap_or(false)
}

/// Fetches the latest non-prerelease release from GitHub.
pub fn latest_release() -> Result<Release> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = ureq::get(&url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call()
        .context("could not reach GitHub")?
        .into_string()
        .context("could not read the release response")?;
    let rel: ReleaseJson =
        serde_json::from_str(&body).context("could not parse the release data")?;
    Ok(Release {
        version: rel.tag_name.trim_start_matches('v').to_owned(),
        notes: rel.body,
        url: rel.html_url,
        assets: rel.assets,
    })
}

/// Whether `latest` is a newer version than `current`, by SemVer precedence:
/// the `x.y.z` core is compared numerically, and a pre-release (`-beta.1`) ranks
/// *below* the matching release — so someone on `2.6.0-beta.1` is correctly
/// offered the final `2.6.0`. Build metadata (`+…`) is ignored.
pub fn is_newer(latest: &str, current: &str) -> bool {
    version_cmp(latest, current) == std::cmp::Ordering::Greater
}

fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (core_a, pre_a) = split_pre(a);
    let (core_b, pre_b) = split_pre(b);
    match core_parts(core_a).cmp(&core_parts(core_b)) {
        Ordering::Equal => {}
        ord => return ord,
    }
    // Same core: a release (no pre-release) outranks any pre-release of it.
    match (pre_a.is_empty(), pre_b.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => cmp_prerelease(pre_a, pre_b),
    }
}

/// Splits a version into its `x.y.z` core and pre-release tag, dropping any `+build`.
fn split_pre(v: &str) -> (&str, &str) {
    let v = v.split('+').next().unwrap_or(v);
    match v.split_once('-') {
        Some((core, pre)) => (core, pre),
        None => (v, ""),
    }
}

/// The three numeric core fields (missing ones default to 0), for ordered compare.
fn core_parts(core: &str) -> [u64; 3] {
    let mut out = [0u64; 3];
    for (i, s) in core.split('.').take(3).enumerate() {
        out[i] = s.parse().unwrap_or(0);
    }
    out
}

/// Compares two pre-release tags per SemVer: dot-separated identifiers, numeric
/// compared numerically (and ranked below alphanumeric), and a shorter tag ranks
/// below a longer one when all preceding identifiers are equal.
fn cmp_prerelease(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut ai = a.split('.');
    let mut bi = b.split('.');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// The release asset name suffix wanted for the given install, per platform.
fn wanted_suffix(kind: &InstallKind) -> &'static str {
    match kind {
        InstallKind::AppImage(_) => "linux-x86_64.AppImage",
        InstallKind::Executable(_) => {
            if cfg!(windows) {
                "windows-x86_64.exe"
            } else if cfg!(target_os = "macos") {
                "macos-aarch64"
            } else {
                // Raw Linux binary asset (no extension; won't match .AppImage/.rpm).
                "linux-x86_64"
            }
        }
        InstallKind::Managed => "",
    }
}

fn select_asset<'a>(release: &'a Release, kind: &InstallKind) -> Option<&'a Asset> {
    let suffix = wanted_suffix(kind);
    if suffix.is_empty() {
        return None;
    }
    release.assets.iter().find(|a| a.name.ends_with(suffix))
}

/// Downloads the matching asset and replaces this install in place. On success
/// the caller should relaunch via [`relaunch`].
pub fn download_and_apply(release: &Release, kind: &InstallKind) -> Result<()> {
    let asset = select_asset(release, kind)
        .context("this release has no download for your platform/install type")?;
    let target = match kind {
        InstallKind::AppImage(p) | InstallKind::Executable(p) => p.clone(),
        InstallKind::Managed => bail!("this install is managed by a package manager"),
    };
    // Download to a temp file in the target's directory so the final move is a
    // same-filesystem rename.
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).ok();
    let mut tmp = tempfile::Builder::new()
        .prefix(".wazowski-update-")
        .tempfile_in(dir)
        .context("could not create a temp file for the download")?;
    let mut reader = ureq::get(&asset.browser_download_url)
        .set("User-Agent", USER_AGENT)
        .call()
        .context("could not download the update")?
        .into_reader();
    std::io::copy(&mut reader, tmp.as_file_mut()).context("could not save the download")?;
    tmp.as_file_mut().sync_all().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755))
            .context("could not make the update executable")?;
    }
    let tmp_path = tmp.into_temp_path();
    match kind {
        // The running AppImage's current_exe() is inside the mount, so replace
        // the .AppImage file directly rather than via self_replace.
        InstallKind::AppImage(p) => {
            tmp_path
                .persist(p)
                .map_err(|e| e.error)
                .context("could not replace the AppImage")?;
        }
        // self_replace handles overwriting the running executable (incl. the
        // Windows rename dance).
        InstallKind::Executable(_) => {
            self_replace::self_replace(&tmp_path)
                .context("could not replace the running executable")?;
            // tmp_path is consumed on success by self_replace moving it; if it
            // still exists, dropping it cleans up.
        }
        InstallKind::Managed => unreachable!(),
    }
    Ok(())
}

/// Relaunches the (now-updated) app and exits this process.
pub fn relaunch(kind: &InstallKind) -> ! {
    if let Some(exe) = kind.launch_target() {
        let _ = std::process::Command::new(exe).spawn();
    }
    std::process::exit(0);
}

// --- Threaded check/apply for the UI ---------------------------------------

/// The result of a background update check.
pub enum CheckOutcome {
    UpToDate,
    Available(Release),
    Error(String),
}

/// A background update check; poll [`take`](CheckHandle::take) for the result.
pub struct CheckHandle {
    cell: Arc<Mutex<Option<CheckOutcome>>>,
}

impl CheckHandle {
    /// Spawns a check against the given current version.
    pub fn spawn(current: String) -> Self {
        let cell = Arc::new(Mutex::new(None));
        let out = cell.clone();
        std::thread::spawn(move || {
            let outcome = match latest_release() {
                Ok(rel) if is_newer(&rel.version, &current) => CheckOutcome::Available(rel),
                Ok(_) => CheckOutcome::UpToDate,
                Err(e) => CheckOutcome::Error(format!("{e:#}")),
            };
            *out.lock().expect("update cell poisoned") = Some(outcome);
        });
        Self { cell }
    }

    /// Returns the outcome once the check finishes (and clears it).
    pub fn take(&self) -> Option<CheckOutcome> {
        self.cell.lock().expect("update cell poisoned").take()
    }
}

/// The result of a background download+apply.
pub enum ApplyOutcome {
    Done,
    Error(String),
}

/// A background download+install; poll [`take`](ApplyHandle::take).
pub struct ApplyHandle {
    cell: Arc<Mutex<Option<ApplyOutcome>>>,
}

impl ApplyHandle {
    pub fn spawn(release: Release, kind: InstallKind) -> Self {
        let cell = Arc::new(Mutex::new(None));
        let out = cell.clone();
        std::thread::spawn(move || {
            let outcome = match download_and_apply(&release, &kind) {
                Ok(()) => ApplyOutcome::Done,
                Err(e) => ApplyOutcome::Error(format!("{e:#}")),
            };
            *out.lock().expect("apply cell poisoned") = Some(outcome);
        });
        Self { cell }
    }

    pub fn take(&self) -> Option<ApplyOutcome> {
        self.cell.lock().expect("apply cell poisoned").take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_version_detection() {
        assert!(is_newer("2.0.6", "2.0.5"));
        assert!(is_newer("2.1.0", "2.0.9"));
        assert!(is_newer("2.0.10", "2.0.9"));
        assert!(!is_newer("2.0.5", "2.0.5"));
        assert!(!is_newer("2.0.4", "2.0.5"));
        // A prerelease core equal to current is not "newer" than the release.
        assert!(!is_newer("2.0.5-beta.1", "2.0.5"));
        // The bug fix: the final release IS newer than its own pre-release, so a
        // beta user is offered the release.
        assert!(is_newer("2.6.0", "2.6.0-beta.1"));
        assert!(is_newer("2.6.0", "2.6.0-beta.3"));
        // Pre-release ordering among betas.
        assert!(is_newer("2.6.0-beta.2", "2.6.0-beta.1"));
        assert!(!is_newer("2.6.0-beta.1", "2.6.0-beta.2"));
        // A higher core always wins regardless of pre-release tags.
        assert!(is_newer("2.6.1", "2.6.0-beta.1"));
        // Build metadata is ignored.
        assert!(!is_newer("2.6.0+ci", "2.6.0"));
    }

    #[test]
    fn asset_suffix_by_kind() {
        assert_eq!(
            wanted_suffix(&InstallKind::AppImage("/x.AppImage".into())),
            "linux-x86_64.AppImage"
        );
        assert!(!wanted_suffix(&InstallKind::Executable("/x".into())).is_empty());
        assert_eq!(wanted_suffix(&InstallKind::Managed), "");
    }

    #[test]
    fn selects_the_right_asset() {
        let release = Release {
            version: "2.0.6".into(),
            notes: String::new(),
            url: String::new(),
            assets: vec![
                Asset { name: "wazowski-v2.0.6-linux-x86_64".into(), browser_download_url: "a".into() },
                Asset {
                    name: "wazowski-v2.0.6-linux-x86_64.AppImage".into(),
                    browser_download_url: "b".into(),
                },
                Asset {
                    name: "wazowski-v2.0.6-linux-x86_64.rpm".into(),
                    browser_download_url: "c".into(),
                },
            ],
        };
        // AppImage install picks the .AppImage, not the raw binary or rpm.
        let a = select_asset(&release, &InstallKind::AppImage("/x.AppImage".into())).unwrap();
        assert!(a.name.ends_with(".AppImage"));
    }
}
