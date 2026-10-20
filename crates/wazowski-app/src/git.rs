//! A git-backed shared source, driven by the system `git` binary.
//!
//! Shelling out to `git` means any host works the same (GitHub, GitLab,
//! Forgejo, …) and the user's existing SSH agent / credential helpers apply.
//! Private repos can authenticate with an HTTPS token (sent as a Basic auth
//! header, never written to the repo config) or an SSH key.

use std::path::PathBuf;
use std::process::Command;

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
        Self { work_dir, url, branch, file, auth, _ssh_key_file: ssh_key_file }
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
        // Commit; a no-op commit returns non-zero, which is fine.
        let committed = self.git(&[
            "-c",
            "user.name=Wazowski",
            "-c",
            "user.email=wazowski@localhost",
            "commit",
            "-m",
            "Update sessions",
        ]);
        if committed.is_err() && !self.is_clean()? {
            committed.context("git commit failed")?;
        }
        Ok(())
    }

    /// Pushes committed changes to the remote (setting upstream on first push).
    pub fn push(&self) -> Result<()> {
        self.ensure_clone()?;
        self.git(&["push", "--set-upstream", "origin", "HEAD"]).context("git push failed")
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
