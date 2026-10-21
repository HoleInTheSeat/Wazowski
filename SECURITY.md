# Security Policy

Wazowski handles credentials (SSH keys, passwords, tokens), so security reports
are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Instead, use GitHub's
private vulnerability reporting:

- Go to the **Security** tab → **Report a vulnerability** (GitHub Private
  Vulnerability Reporting), or
- Open a draft **Security Advisory** on this repository.

Include what you found, how to reproduce it, and the impact. We'll acknowledge
the report and work on a fix; please allow reasonable time to patch before any
public disclosure.

## Supported versions

Security fixes land on the latest release. Please upgrade to the newest version
(the app has a built-in updater) before reporting.

## How Wazowski protects credentials

For context when assessing reports:

- **Secrets live only in an encrypted vault.** Passwords, SSH keypairs, and
  tokens are stored in a single file encrypted with **XChaCha20-Poly1305**, with
  the key derived from the master password via **Argon2id**. Secrets are zeroized
  in memory where practical.
- **Nothing sensitive is written in plaintext.** Session, source, and settings
  files reference vault entries by id — they never contain the secret itself.
  SFTP server passwords are kept in the OS keyring, not on disk.
- **Git auth is never written to the repo config.** HTTPS tokens are sent as an
  `Authorization` header for a single invocation; SSH keys are materialised to a
  private (0600) temp file only for the duration of a command.
- **The optional keyring auto-unlock** caches the vault key in the OS keyring
  (Secret Service / Keychain / Credential Manager), never on disk in the clear.

Out of scope: an attacker with full read access to the machine *while the vault
is unlocked*, or who knows the master password, can read the secrets — that is by
design, the same trust model as any local credential manager.
