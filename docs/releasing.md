# Releasing & CI

How Wazowski is built, tested, versioned, and shipped. This is the reference for
cutting a release, pushing a pre-release, and understanding the GitHub Actions
automation — so the process isn't locked in anyone's head.

The automation lives in two workflow files:

- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — the quality gate.
- [`.github/workflows/release.yml`](../.github/workflows/release.yml) — builds all
  platforms and publishes a GitHub Release.

> **Mental model:** GitHub Actions is *reactive*. Nothing auto-tags or
> auto-releases on a timer. **You** push a git tag; the release workflow is just
> listening for that event and reacts to it. "Cut a release" = push a `v*` tag.

---

## CI — the quality gate

**Trigger:** every push to `main` and every pull request targeting `main`.

**What it does** (on `ubuntu-latest`):

1. Checks out the repo, installs the Linux GUI build dependencies and the Rust
   toolchain (with Clippy).
2. `cargo clippy --workspace --all-targets -- -D warnings` — the hard gate.
   `-D warnings` turns **every** warning (including deprecations) into an error,
   so a yellow note fails the build. This is what rejects, e.g., a deprecated API
   call.
3. `cargo test --workspace`.

If either command exits non-zero, the run is red → that's the ✗ you see on a
commit or PR. There are **no required status checks** configured, so a red CI
does not *physically* block a merge — but treat green as the bar before merging.

Reproduce the gate locally before pushing:

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

---

## Release — build & publish

**Trigger:** pushing a tag matching `v*` (e.g. `v2.5.1`, `v2.6.0-beta.1`).

```yaml
on:
  push:
    tags: ["v*"]
permissions:
  contents: write     # lets the run's auto GITHUB_TOKEN create the Release
```

It never needs a stored secret: every run gets an automatic `GITHUB_TOKEN`, and
`permissions: contents: write` is what lets that token publish a Release.

### Jobs

| Job | Runner | Produces |
|---|---|---|
| **build** (matrix) | ubuntu / windows | the raw Linux & Windows binaries |
| **package-linux** | ubuntu | Fedora **RPM** + portable **AppImage** |
| **package-windows** | windows | Inno Setup **installer** (`…-setup.exe`) |
| **package-macos** | macos | a **`.app` bundle in a `.dmg`** + the raw macOS binary |
| **release** | ubuntu | gathers all artifacts → publishes the GitHub Release |

**The matrix** writes the Linux/Windows build once and runs it on both OSes:

```yaml
strategy:
  matrix:
    include:
      - { os: ubuntu-latest,  platform: linux-x86_64,   bin: wazowski }
      - { os: windows-latest, platform: windows-x86_64, bin: wazowski.exe }
runs-on: ${{ matrix.os }}
```

macOS is its own `package-macos` job (it needs extra steps — bundle, icon, sign,
`.dmg` — that don't fit the matrix). It emits **both** the raw `…-macos-aarch64`
binary (what the in-app updater matches on) **and** a `Wazowski.app` inside a
`.dmg` for people to download and drag to Applications. The `.dmg` is **ad-hoc
signed only, not notarized**, so first launch still trips Gatekeeper — see
[Troubleshooting](troubleshooting.md). Removing that warning entirely would
require a paid Apple **Developer ID** certificate and **notarization**.

**Files move between jobs via the artifact store** — each job runs on its own
fresh VM, so build jobs `actions/upload-artifact` and the publish job
`actions/download-artifact` to collect everything before attaching it.

**Publishing** uses `softprops/action-gh-release`:

```yaml
- uses: softprops/action-gh-release@v3
  with:
    files: artifacts/**/*
    generate_release_notes: true
    prerelease: ${{ contains(github.ref_name, '-') }}
```

The asset filenames carry the tag, e.g. `wazowski-v2.5.1-linux-x86_64.rpm`.

### The macOS caveat (important)

GitHub's macOS-arm64 hosted runners are frequently capacity-constrained and a run
can fail to even *acquire* one. Two guards keep that from blocking a release:

- `continue-on-error: ${{ matrix.os == 'macos-latest' }}` on the build job.
- The publish job runs `if: ${{ !cancelled() && needs.package-linux.result == 'success' }}`.

So **Linux + Windows still publish even if macOS never ran** — but the overall
run shows red, and the macOS assets are missing. That red is infrastructure, not
your code. To backfill macOS once capacity frees up:

```sh
# re-run just the failed macOS job on that release run
gh run list --workflow release.yml --limit 5
gh run rerun <run-id> --failed
```

When `package-macos` succeeds, download its artifact bundle and attach everything
to the release (or re-run the whole workflow for the tag so the publish job
re-collects it):

```sh
gh run download <run-id> -n wazowski-macos -D /tmp/macos
gh release upload <tag> /tmp/macos/* --clobber   # the .dmg and the raw binary
```

### Caching

All Rust jobs use `Swatinem/rust-cache@v2`, so compiled dependencies are reused
across runs (these are the `v0-rust-*` caches in the repo's Actions → Caches).
GitHub caps cache at 10 GB/repo and auto-evicts the least-recently-used entries;
a "near limit" notice is harmless. To prune manually: `gh cache list` /
`gh cache delete <id>` (or `--all`).

---

## Versioning

Semantic-ish `x.y.z`. The whole workspace shares one version
(`[workspace.package] version` in the root `Cargo.toml`; crates inherit it via
`version.workspace = true`).

- **x** (major) — a large overhaul (e.g. the native RDP rewrite).
- **y** (minor) — a feature was added, or a major, measurable performance win.
- **z** (patch) — bug fixes, small UI tweaks, dependency/maintenance updates.

A dependency bump — even a big one like an egui major upgrade — is maintenance, so
it's a **patch** bump unless it ships a user-facing feature.

---

## Runbook: cut a release

Pre-flight — be on an up-to-date, clean `main` with green CI:

```sh
git checkout main && git pull origin main
git status                      # must be clean
gh run list --branch main --limit 1   # last CI run should be success
```

1. **Bump the version** in the root `Cargo.toml` (`[workspace.package] version`).
2. **Refresh the lockfile** (the version appears there too):
   ```sh
   cargo check --workspace
   ```
3. **Commit:**
   ```sh
   git add Cargo.toml Cargo.lock
   git commit -m "Release X.Y.Z"
   ```
4. **Tag** (annotated) and **push the commit *and* the tag separately** — a plain
   `git push` does *not* send tags:
   ```sh
   git tag -a vX.Y.Z -m "Release X.Y.Z"
   git push origin main
   git push origin vX.Y.Z          # <-- this is what triggers the build
   ```
5. **Watch & verify:**
   ```sh
   gh run list --workflow release.yml --limit 1
   gh release view vX.Y.Z --json tagName,assets --jq '{tag:.tagName, assets:[.assets[].name]}'
   ```
   Expect Linux (binary + `.rpm` + `.AppImage`), Windows (`-setup.exe` + portable
   `.exe`), and macOS (`-macos-aarch64` binary + `.dmg`). If macOS is missing, see
   the caveat above.

> **Forgot the tag?** If you pushed the "Release X.Y.Z" commit but no release
> appeared, you likely skipped the tag push — the commit only changes the version
> *number*; the **tag** is what ships it. Just create and push the tag on that
> commit (`git tag -a vX.Y.Z … && git push origin vX.Y.Z`); nothing needs redoing.

---

## Build the Linux artifacts locally

To produce a real build without waiting on CI, `scripts/build-linux.sh` runs the
same steps as the Linux release jobs and drops the binary, Fedora **RPM**, and
portable **AppImage** into `dist/`:

```sh
scripts/build-linux.sh
```

One-time prerequisites (Fedora): `sudo dnf install ImageMagick openssl-devel
pkgconf-pkg-config wget file` and `cargo install cargo-generate-rpm --locked`.
For just running the app, `cargo run --release -p wazowski-app` is quicker.
Windows and macOS artifacts can only be built on those platforms, so they still
come from CI.

## Pre-releases

A pre-release is just a tag whose semver has a **hyphen** suffix — `-alpha.N`,
`-beta.N`, `-rc.N`. The workflow auto-flags it:
`prerelease: ${{ contains(github.ref_name, '-') }}`.

```sh
# optional: set Cargo.toml version = "2.6.0-beta.1" so the binary self-reports it
cargo check --workspace
git commit -am "Pre-release 2.6.0-beta.1"
git push origin main
git tag -a v2.6.0-beta.1 -m "Pre-release 2.6.0-beta.1"
git push origin v2.6.0-beta.1
gh release view v2.6.0-beta.1 --json isPrerelease --jq .isPrerelease   # -> true
```

Behaviour:

- GitHub marks it **Pre-release** (badge; it does **not** become "Latest").
- The in-app updater calls `…/releases/latest`, which **excludes** pre-releases —
  so stable users are **not** auto-offered a beta. Testers download it manually
  from the Releases page.
- Any `v*` tag builds, so you can also tag a **feature-branch** commit to get test
  binaries without touching `main`.
- The updater's version compare is **SemVer-aware** (`is_newer` in `update.rs`): a
  pre-release ranks *below* its release, so someone on `2.6.0-beta.1` **is** offered
  the final `2.6.0`. (This was fixed in 2.6.0; clients on *older* betas still
  running the pre-fix compare won't auto-nudge and update manually.)

When ready, cut the final by tagging `vX.Y.Z` with **no hyphen** → normal release,
becomes Latest, updater offers it.

---

## Dependabot

Dependabot opens PRs for dependency bumps (Cargo crates and GitHub Actions); each
runs CI like any PR.

- **Green PRs** — merge normally (Squash and merge). From the CLI:
  `gh pr merge <n> --squash --delete-branch`.
- **Conflicts** — bumps usually conflict on `Cargo.lock` after another one merges.
  Comment `@dependabot rebase` (Dependabot also auto-rebases open PRs when `main`
  moves) and it re-resolves; wait for green, then merge.
- **Order** — merge one, let the next rebase, merge it; repeat.
- **Big migrations** (e.g. an egui major) — a Dependabot PR only edits the
  manifest/lock; it can't include the code changes a breaking bump needs, and
  coupled crates (egui + eframe) must bump together. Do these as a **manual
  branch** that bumps everything *and* fixes the code, verify
  `clippy -D warnings` + run the app, open a normal PR, then **close** the
  superseded Dependabot PRs
  (`gh pr close <n> --comment "Superseded by #<pr>"`).

---

## Appendix — a minimal workflow from scratch

You grow a setup like this; you don't write it all at once.

Minimal CI (`.github/workflows/ci.yml`):

```yaml
name: CI
on: { push: { branches: [main] } }
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test
```

Minimal auto-release on tags (`.github/workflows/release.yml`):

```yaml
name: Release
on: { push: { tags: ["v*"] } }
permissions: { contents: write }
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - uses: softprops/action-gh-release@v3
        with: { files: target/release/wazowski }
```

From there: add a `strategy.matrix` for more platforms, split packaging into their
own jobs, pass files with `upload-artifact`/`download-artifact`, and add
`Swatinem/rust-cache`. That progression is exactly how the current
`release.yml` grew. The `uses:` steps are reusable **Marketplace** actions; each
documents its inputs in its own README. Full syntax: <https://docs.github.com/actions>.
