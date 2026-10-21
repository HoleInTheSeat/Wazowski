//! A git-backed shared source, driven by the system `git` binary.
//!
//! Shelling out to `git` means any host works the same (GitHub, GitLab,
//! Forgejo, …) and the user's existing SSH agent / credential helpers apply.
//! Private repos can authenticate with an HTTPS token (sent as a Basic auth
//! header, never written to the repo config) or an SSH key.

use std::cell::OnceCell;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;

/// How a git remote authenticates.
#[derive(Clone)]
pub enum GitAuth {
    /// Public repo, or rely on the user's ambient git credentials.
    None,
    /// HTTPS with a personal access token (works for GitHub/GitLab/Forgejo/…).
    Https { username: String, token: String },
    /// SSH with an explicit key file (`key_path`), an inline private key
    /// (`inline_key`, e.g. from the vault — written to a temp file for `ssh -i`),
    /// or neither (the agent / default key).
    Ssh { key_path: Option<PathBuf>, inline_key: Option<String> },
}

/// A working clone of a shared-sessions repo.
pub struct GitRepo {
    work_dir: PathBuf,
    url: String,
    /// Branch to track; empty means the remote default.
    branch: String,
    /// Path of the sessions file within the repo.
    file: String,
    auth: GitAuth,
    /// A temp file holding an inline SSH key (from the vault), written for the
    /// life of this repo so `ssh -i` can read it. Deleted when the repo drops.
    _ssh_key_file: Option<tempfile::TempPath>,
    /// The GitHub account behind the HTTPS token, looked up once and cached
    /// (`None` when there's no token, the remote isn't github.com, or the lookup
    /// failed — e.g. offline). This is the preferred commit identity.
    github_cache: OnceCell<Option<(String, String)>>,
}

impl GitRepo {
    pub fn new(
        work_dir: PathBuf,
        url: String,
        branch: String,
        file: String,
        auth: GitAuth,
    ) -> Self {
        // An inline SSH key is materialised to a private temp file, and the auth
        // rewritten to point `ssh -i` at it. On Unix the temp file is created
        // 0600 by `tempfile`; the handle is closed (TempPath) so ssh can read it.
        let (auth, ssh_key_file) = match auth {
            GitAuth::Ssh { inline_key: Some(key), .. } => match write_temp_key(&key) {
                Ok(path) => (
                    GitAuth::Ssh { key_path: Some(path.to_path_buf()), inline_key: None },
                    Some(path),
                ),
                // If we can't write the temp key, fall back to the agent/default.
                Err(_) => (GitAuth::Ssh { key_path: None, inline_key: None }, None),
            },
            other => (other, None),
        };
        Self {
            work_dir,
            url,
            branch,
            file,
            auth,
            _ssh_key_file: ssh_key_file,
            github_cache: OnceCell::new(),
        }
    }

    /// Fetches the latest and returns the sessions-file bytes (`None` if absent).
    /// Errors if the remote is unreachable or gone, so callers can go offline.
    pub fn fetch(&self) -> Result<Option<Vec<u8>>> {
        self.ensure_clone()?;
        // `fetch` reaching the remote is the online signal (a deleted repo or a
        // dropped network fails here). Then fast-forward the working tree.
        self.git(&["fetch", "--prune"]).context("could not reach the git remote")?;
        let _ = self.git(&["merge", "--ff-only"]);
        let path = self.work_dir.join(&self.file);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading the sessions file in the clone"),
        }
    }

    /// Writes the sessions file and commits it locally, without pushing. The
    /// commit becomes an "unpushed change" until [`push`](Self::push) runs.
    pub fn commit(&self, bytes: &[u8]) -> Result<()> {
        self.ensure_clone()?;
        let path = self.work_dir.join(&self.file);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&path, bytes).context("writing the sessions file")?;
        self.git(&["add", "--", &self.file]).context("git add failed")?;
        // Attribute the commit to the user, not "Wazowski": use their own git
        // identity when configured, else a derived one (GitHub login / OS user).
        let mut args: Vec<String> = self.identity_args();
        args.extend(["commit".into(), "-m".into(), "Update sessions".into()]);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        // Commit; a no-op commit returns non-zero, which is fine.
        let committed = self.git(&argv);
        if committed.is_err() && !self.is_clean()? {
            committed.context("git commit failed")?;
        }
        Ok(())
    }

    /// The `-c user.name=…`/`-c user.email=…` arguments to attribute the commit.
    /// Preference order: the GitHub account behind the token (primary), then the
    /// user's own configured git identity (used unchanged → empty args), then the
    /// OS user running Wazowski.
    fn identity_args(&self) -> Vec<String> {
        let identity = self.token_identity().or_else(|| {
            // No token identity: prefer the user's own git config if they have one.
            if self.has_git_identity() {
                return None; // empty args → git uses the configured identity
            }
            // Last resort: the OS user running Wazowski.
            let user = os_username();
            Some((user.clone(), format!("{user}@localhost")))
        });
        match identity {
            Some((name, email)) => vec![
                "-c".into(),
                format!("user.name={name}"),
                "-c".into(),
                format!("user.email={email}"),
            ],
            None => Vec::new(),
        }
    }

    /// Whether git already resolves a committer identity here (global/local
    /// `user.name` and `user.email`), in which case we don't override it.
    fn has_git_identity(&self) -> bool {
        self.config_value("user.name").is_some() && self.config_value("user.email").is_some()
    }

    /// Reads a non-empty git config value in the work dir (honours global config).
    fn config_value(&self, key: &str) -> Option<String> {
        let out = self.command(Some(&self.work_dir)).args(["config", "--get", key]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let val = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        (!val.is_empty()).then_some(val)
    }

    /// The GitHub account behind the HTTPS token (`(name, email)`), looked up
    /// once and cached. `None` when there's no token, the remote isn't github.com,
    /// or the lookup failed. This is the preferred commit identity.
    fn token_identity(&self) -> Option<(String, String)> {
        self.github_cache
            .get_or_init(|| match &self.auth {
                GitAuth::Https { token, .. } if is_github(&self.url) => github_identity(token),
                _ => None,
            })
            .clone()
    }

    /// Pushes committed changes to the remote (setting upstream on first push).
    ///
    /// First fetches and rebases local commits onto the updated upstream, so a
    /// sibling source that shares the same repo (a different file in it) doesn't
    /// get rejected as non-fast-forward after the other one pushes. A real
    /// conflict (the same file changed on both sides) aborts the rebase and lets
    /// the push surface the rejection.
    pub fn push(&self) -> Result<()> {
        self.ensure_clone()?;
        // Bring in anything pushed to the same branch since our last fetch.
        let _ = self.git(&["fetch", "--prune"]);
        if self.has_upstream() && self.git(&["rebase", "@{u}"]).is_err() {
            let _ = self.git(&["rebase", "--abort"]);
        }
        self.git(&["push", "--set-upstream", "origin", "HEAD"]).context("git push failed")
    }

    /// Whether HEAD has a tracked upstream branch (i.e. it has been pushed).
    fn has_upstream(&self) -> bool {
        self.command(Some(&self.work_dir))
            .args(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Writes the sessions file, commits, and pushes in one step.
    pub fn publish(&self, bytes: &[u8]) -> Result<()> {
        self.commit(bytes)?;
        self.push()
    }

    /// Whether the local clone has changes not yet on the remote: uncommitted
    /// working-tree changes, or commits ahead of the upstream (or, before the
    /// first push, any local commits at all).
    pub fn has_unpushed(&self) -> Result<bool> {
        if !self.work_dir.join(".git").is_dir() {
            return Ok(false);
        }
        if !self.is_clean()? {
            return Ok(true);
        }
        // Ahead of the tracked upstream?
        let out = self
            .command(Some(&self.work_dir))
            .args(["rev-list", "--count", "@{u}..HEAD"])
            .output()?;
        if out.status.success() {
            let n: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0);
            return Ok(n > 0);
        }
        // No upstream yet (never pushed): any commit on HEAD is unpushed.
        let out =
            self.command(Some(&self.work_dir)).args(["rev-list", "--count", "HEAD"]).output()?;
        if !out.status.success() {
            return Ok(false); // no commits at all
        }
        let n: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0);
        Ok(n > 0)
    }

    /// Discards local commits/changes, resetting the clone to match the remote.
    pub fn discard(&self) -> Result<()> {
        self.ensure_clone()?;
        let _ = self.git(&["fetch", "--prune"]);
        if self.git(&["reset", "--hard", "@{u}"]).is_err() {
            let branch = if self.branch.is_empty() { "HEAD" } else { self.branch.as_str() };
            let _ = self.git(&["reset", "--hard", &format!("origin/{branch}")]);
        }
        let _ = self.git(&["clean", "-fd"]);
        Ok(())
    }

    /// Clones the repo on first use.
    fn ensure_clone(&self) -> Result<()> {
        if self.work_dir.join(".git").is_dir() {
            return Ok(());
        }
        if let Some(parent) = self.work_dir.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let dir = self.work_dir.to_string_lossy().into_owned();
        // Clone without pinning a branch so even an empty repo clones cleanly.
        self.git_in(None, &["clone", &self.url, &dir]).context("git clone failed")?;
        // Switch to the requested branch if one was given (best effort; it may
        // not exist yet in an empty repo, in which case the first publish makes it).
        if !self.branch.is_empty() {
            let _ = self.git(&["checkout", &self.branch]);
            let _ = self.git(&["checkout", "-B", &self.branch]);
        }
        Ok(())
    }

    /// Whether the working tree has no uncommitted changes.
    fn is_clean(&self) -> Result<bool> {
        let out = self.command(Some(&self.work_dir)).args(["status", "--porcelain"]).output()?;
        Ok(out.stdout.is_empty())
    }

    /// Runs a git command in the work dir.
    fn git(&self, args: &[&str]) -> Result<()> {
        self.git_in(Some(&self.work_dir), args)
    }

    #[cfg(test)]
    fn summarize(stderr: &str) -> String {
        summarize_git_error(stderr)
    }

    fn git_in(&self, cwd: Option<&std::path::Path>, args: &[&str]) -> Result<()> {
        let out = match self.command(cwd).args(args).output() {
            Ok(out) => out,
            // The git binary isn't on PATH. This is the common Windows case
            // (Git for Windows isn't installed by default), so say so plainly.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "git is not installed or not on PATH — install Git \
                     (https://git-scm.com/downloads) and restart Wazowski"
                );
            }
            Err(e) => return Err(e).context("could not run git"),
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("{}", summarize_git_error(&stderr));
        }
        Ok(())
    }

    /// Builds a `git` command with auth wired in and prompts disabled.
    fn command(&self, cwd: Option<&std::path::Path>) -> Command {
        let mut cmd = Command::new("git");
        if let Some(dir) = cwd {
            cmd.arg("-C").arg(dir);
        }
        // On Windows, run git (and the ssh/credential helpers it spawns) without
        // flashing a console window. CREATE_NO_WINDOW = 0x08000000.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        // Never block on an interactive credential/host prompt.
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        match &self.auth {
            GitAuth::None => {}
            GitAuth::Https { username, token } => {
                // Send Basic auth as a header so the token isn't written to .git/config.
                let user = if username.is_empty() { "x-access-token" } else { username };
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{user}:{token}"));
                cmd.arg("-c").arg(format!("http.extraHeader=Authorization: Basic {encoded}"));
            }
            GitAuth::Ssh { key_path, .. } => {
                let mut ssh =
                    String::from("ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new");
                if let Some(key) = key_path {
                    // Quote the path so spaces (common on Windows) don't split it.
                    ssh.push_str(&format!(" -i \"{}\" -o IdentitiesOnly=yes", key.display()));
                }
                cmd.env("GIT_SSH_COMMAND", ssh);
            }
        }
        cmd
    }
}

/// Turns git's multi-line stderr into a single useful message. Git often wraps
/// the real cause ("Permission denied (publickey)", "Authentication failed", a
/// `fatal:`/`error:` line) above a generic "Please make sure you have the correct
/// access rights / and the repository exists." trailer — so the *last* line is
/// usually the least useful. Prefer the informative lines, dropping noise.
fn summarize_git_error(stderr: &str) -> String {
    const SIGNALS: [&str; 7] = [
        "permission denied",
        "authentication failed",
        "could not read from remote",
        "repository not found",
        "fatal:",
        "error:",
        "host key verification failed",
    ];
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        // Drop git's generic access-rights trailer, which hides the real cause.
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            !(low.starts_with("please make sure")
                || low == "and the repository exists."
                || low.starts_with("cloning into"))
        })
        .collect();
    let signal: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            SIGNALS.iter().any(|s| low.contains(s))
        })
        .collect();
    let chosen = if !signal.is_empty() { signal } else { lines };
    let msg = chosen.join("; ");
    if msg.is_empty() { "git error".to_owned() } else { msg }
}

/// Whether a remote URL points at github.com (HTTPS or SSH form).
fn is_github(url: &str) -> bool {
    let low = url.to_ascii_lowercase();
    low.contains("github.com")
}

/// The OS user running Wazowski (for commit attribution when nothing better is
/// known). Falls back to "wazowski" if the environment says nothing.
fn os_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "wazowski".to_owned())
}

/// Looks up the GitHub account behind a personal-access token, returning
/// `(name, email)` where the email is the account's `noreply` address so the
/// commit links to that GitHub user. `None` on any network/parse failure.
fn github_identity(token: &str) -> Option<(String, String)> {
    let body = ureq::get("https://api.github.com/user")
        .set("Authorization", &format!("Bearer {token}"))
        .set("User-Agent", "Wazowski")
        .set("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(5))
        .call()
        .ok()?
        .into_string()
        .ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let login = json.get("login")?.as_str()?.to_owned();
    let id = json.get("id")?.as_i64()?;
    // Prefer the profile name; fall back to the login.
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&login)
        .to_owned();
    let email = format!("{id}+{login}@users.noreply.github.com");
    Some((name, email))
}

/// Writes an inline private key to a private temp file for `ssh -i`, returning a
/// path guard that deletes the file when dropped. On Unix `tempfile` creates the
/// file with 0600 permissions; we re-assert that explicitly for safety.
fn write_temp_key(key: &str) -> Result<tempfile::TempPath> {
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .prefix("wazowski-git-key-")
        .tempfile()
        .context("could not create a temp key file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .context("could not restrict the temp key file")?;
    }
    // OpenSSH requires the key to end with a newline.
    let mut bytes = key.as_bytes().to_vec();
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    file.write_all(&bytes).context("could not write the temp key file")?;
    file.flush().ok();
    Ok(file.into_temp_path())
}

#[cfg(test)]
mod tests {
    use super::GitRepo;

    #[test]
    fn surfaces_permission_denied_over_the_trailer() {
        let stderr = "Cloning into '/x'...\n\
                      git@github.com: Permission denied (publickey).\n\
                      fatal: Could not read from remote repository.\n\n\
                      Please make sure you have the correct access rights\n\
                      and the repository exists.\n";
        let msg = GitRepo::summarize(stderr);
        assert!(msg.contains("Permission denied (publickey)"), "got: {msg}");
        assert!(!msg.contains("and the repository exists"), "trailer should be dropped: {msg}");
    }

    #[test]
    fn falls_back_to_all_lines_when_no_signal() {
        assert_eq!(GitRepo::summarize("weird one-off problem"), "weird one-off problem");
        assert_eq!(GitRepo::summarize("   \n  \n"), "git error");
    }
}
