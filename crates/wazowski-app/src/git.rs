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
    /// SSH, optionally with an explicit private key (else the agent/default key).
    Ssh { key_path: Option<PathBuf> },
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
}

impl GitRepo {
    pub fn new(
        work_dir: PathBuf,
        url: String,
        branch: String,
        file: String,
        auth: GitAuth,
    ) -> Self {
        Self { work_dir, url, branch, file, auth }
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
            bail!("{}", stderr.trim().lines().last().unwrap_or("git error"));
        }
        Ok(())
    }

    /// Builds a `git` command with auth wired in and prompts disabled.
    fn command(&self, cwd: Option<&std::path::Path>) -> Command {
        let mut cmd = Command::new("git");
        if let Some(dir) = cwd {
            cmd.arg("-C").arg(dir);
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
            GitAuth::Ssh { key_path } => {
                let mut ssh =
                    String::from("ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new");
                if let Some(key) = key_path {
                    ssh.push_str(&format!(" -i {}", key.display()));
                }
                cmd.env("GIT_SSH_COMMAND", ssh);
            }
        }
        cmd
    }
}
