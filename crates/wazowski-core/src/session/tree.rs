//! The exploded file-tree format for a [`SessionStore`].
//!
//! Instead of one TOML file holding a whole store, a store can be laid out as a
//! directory tree: each folder is a directory with a `.folder` sidecar, and each
//! session is a `<slug>.wzsession` file inside its folder's directory. Directory
//! and file names are slugs; the human display name lives *inside* the file, so
//! renames don't require path-legal names and two things can share a display
//! name. This is what makes a git-backed shared source merge cleanly: editing
//! one session touches one file.
//!
//! [`explode`] turns a store into `(relative path, bytes)` pairs; [`assemble`]
//! walks a directory back into a store. Round-tripping preserves sessions,
//! folders, styles, descriptions and the stable UUIDs — but **never** a
//! username or password: `.wzsession` files carry no credentials, so [`assemble`]
//! always yields sessions whose `username` is empty (prompt) or whose auth is a
//! vault reference.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{
    Auth, FolderMeta, FolderStyle, Protocol, RdpQuality, Session, SessionStore, VncQuality,
    default_port,
};

/// Extension for a session file (without the dot).
pub const SESSION_EXT: &str = "wzsession";
/// Sidecar file naming a directory as a folder (and carrying its metadata).
pub const FOLDER_FILE: &str = ".folder";

/// The on-disk shape of a `.folder` sidecar.
#[derive(Default, Serialize, Deserialize)]
struct FolderDoc {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    icon: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    color: Option<[u8; 3]>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
}

/// The on-disk shape of a `.wzsession` file: a [`Session`] without its `username`
/// (dropped — prompt or vault only) or `folder` (implied by the directory).
#[derive(Serialize, Deserialize)]
struct SessionDoc {
    id: String,
    name: String,
    #[serde(default)]
    protocol: Protocol,
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    domain: String,
    #[serde(default)]
    auth: Auth,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    legacy: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    icon: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    color: Option<[u8; 3]>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    sftp_auto_refresh: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    vnc_view_only: bool,
    #[serde(default)]
    vnc_quality: VncQuality,
    #[serde(default, skip_serializing_if = "is_zero")]
    rdp_width: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    rdp_height: u16,
    #[serde(default)]
    rdp_quality: RdpQuality,
}

fn is_zero(n: &u16) -> bool {
    *n == 0
}

impl SessionDoc {
    fn from_session(s: &Session) -> Self {
        Self {
            id: s.id.clone(),
            name: s.name.clone(),
            protocol: s.protocol,
            host: s.host.clone(),
            port: s.port,
            domain: s.domain.clone(),
            auth: s.auth.clone(),
            legacy: s.legacy,
            icon: s.icon.clone(),
            color: s.color,
            sftp_auto_refresh: s.sftp_auto_refresh,
            vnc_view_only: s.vnc_view_only,
            vnc_quality: s.vnc_quality,
            rdp_width: s.rdp_width,
            rdp_height: s.rdp_height,
            rdp_quality: s.rdp_quality,
        }
    }

    /// Rebuilds a [`Session`] in the given folder. `username` is always empty —
    /// the format carries no credentials.
    fn into_session(self, folder: String) -> Session {
        let mut auth = self.auth;
        auth.normalize();
        Session {
            id: self.id,
            name: self.name,
            folder,
            protocol: self.protocol,
            host: self.host,
            port: self.port,
            username: String::new(),
            domain: self.domain,
            auth,
            legacy: self.legacy,
            icon: self.icon,
            color: self.color,
            sftp_auto_refresh: self.sftp_auto_refresh,
            vnc_view_only: self.vnc_view_only,
            vnc_quality: self.vnc_quality,
            rdp_width: self.rdp_width,
            rdp_height: self.rdp_height,
            rdp_quality: self.rdp_quality,
        }
    }
}

// ---- explode ---------------------------------------------------------------

/// Serializes a store into `(relative path, bytes)` pairs: the root `.folder`,
/// one `.folder` per folder directory, and one `.wzsession` per session.
///
/// Call [`SessionStore::ensure_ids`] first so the emitted UUIDs are stable across
/// calls; without it, folders/root lacking an id simply emit an empty one.
pub fn explode(store: &SessionStore) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out: Vec<(PathBuf, Vec<u8>)> = Vec::new();

    // Root `.folder`: the collection's own identity, name, appearance, description.
    let root = FolderDoc {
        id: store.id.clone(),
        name: store.name.clone(),
        icon: store.icon.clone(),
        color: store.color,
        description: store.description.clone(),
    };
    out.push((PathBuf::from(FOLDER_FILE), to_toml(&root)));

    // Assign a slug directory path to each folder (unique among siblings).
    let folder_paths = store.all_folder_paths();
    let slugs = slug_paths(&folder_paths);
    for disp in &folder_paths {
        let dir = &slugs[disp];
        let meta = store.folder_meta.get(disp).cloned().unwrap_or_default();
        let style = store.folder_styles.get(disp).cloned().unwrap_or_default();
        let doc = FolderDoc {
            id: meta.id,
            name: split_last(disp).1.to_owned(),
            icon: style.icon,
            color: style.color,
            description: meta.description,
        };
        out.push((dir.join(FOLDER_FILE), to_toml(&doc)));
    }

    // Sessions, each a slug file unique among sibling session files.
    let mut used: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    for s in &store.sessions {
        let dir = if s.folder.is_empty() {
            PathBuf::new()
        } else {
            slugs.get(&s.folder).cloned().unwrap_or_default()
        };
        let taken = used.entry(dir.clone()).or_default();
        let slug = unique_slug(&slugify(&s.name), taken);
        taken.insert(slug.clone());
        out.push((dir.join(format!("{slug}.{SESSION_EXT}")), to_toml(&SessionDoc::from_session(s))));
    }

    out
}

/// Writes [`explode`]'s output under `root`, creating directories as needed.
/// A full write into a clean directory; it does not remove files already there
/// (use [`sync_tree`] for an incremental, stale-file-aware write).
pub fn write_tree(store: &SessionStore, root: &Path) -> Result<()> {
    for (rel, bytes) in explode(store) {
        let path = root.join(&rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        fs::write(&path, &bytes).with_context(|| format!("could not write {}", path.display()))?;
    }
    Ok(())
}

/// Reconciles the tree under `root` to match `store`: writes each current file
/// (only when its bytes changed, to avoid needless churn), then removes any
/// `.folder`/`.wzsession` left over from a previous state and prunes the empty
/// directories that leaves behind. `.git` and any non-tree files are untouched.
/// This is what a backend calls on each mutation, so git sees exactly the files
/// that actually changed and independent edits merge cleanly.
pub fn sync_tree(store: &SessionStore, root: &Path) -> Result<()> {
    let files = explode(store);
    let keep: BTreeSet<PathBuf> = files.iter().map(|(p, _)| p.clone()).collect();
    for (rel, bytes) in &files {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        if fs::read(&path).ok().as_deref() != Some(bytes.as_slice()) {
            fs::write(&path, bytes).with_context(|| format!("could not write {}", path.display()))?;
        }
    }
    prune_stale(root, &keep)?;
    Ok(())
}

/// Mirrors the tree files under `src` into `dst` (changed files only), then
/// prunes from `dst` anything no longer in `src`. Used for a folder share, whose
/// local mirror and shared directory are kept in step without going through git.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let files = collect_tree_files(src)?;
    let keep: BTreeSet<PathBuf> = files.iter().cloned().collect();
    for rel in &files {
        let from = src.join(rel);
        let to = dst.join(rel);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        let bytes = fs::read(&from).with_context(|| format!("could not read {}", from.display()))?;
        if fs::read(&to).ok().as_deref() != Some(bytes.as_slice()) {
            fs::write(&to, &bytes).with_context(|| format!("could not write {}", to.display()))?;
        }
    }
    prune_stale(dst, &keep)?;
    Ok(())
}

/// Relative paths of every `.folder`/`.wzsession` under `root` (recursively,
/// skipping `.git`). An absent `root` yields an empty list.
pub fn collect_tree_files(root: &Path) -> Result<Vec<PathBuf>> {
    fn rec(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", dir.display())),
        };
        for entry in rd {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            if name == ".git" {
                continue;
            }
            if entry.file_type()?.is_dir() {
                rec(root, &path, out)?;
            } else if is_tree_file(&path) {
                out.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    rec(root, root, &mut out)?;
    Ok(out)
}

/// Whether `root` holds any tree files at all (so a store exists there, vs an
/// empty/fresh repo or a missing directory).
pub fn tree_present(root: &Path) -> bool {
    collect_tree_files(root).map(|v| !v.is_empty()).unwrap_or(false)
}

/// Whether a path is a `.folder` sidecar or a `.wzsession` file.
fn is_tree_file(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()) == Some(FOLDER_FILE)
        || path.extension().and_then(|e| e.to_str()) == Some(SESSION_EXT)
}

/// Deletes tree files under `root` whose relative path is not in `keep`, then
/// removes the directories that empties (never `.git`).
fn prune_stale(root: &Path, keep: &BTreeSet<PathBuf>) -> Result<()> {
    fn rec(root: &Path, dir: &Path, keep: &BTreeSet<PathBuf>) -> Result<()> {
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("could not read {}", dir.display())),
        };
        for entry in rd {
            let entry = entry?;
            let path = entry.path();
            if entry.file_name() == ".git" {
                continue;
            }
            if entry.file_type()?.is_dir() {
                rec(root, &path, keep)?;
                // Remove the directory if pruning emptied it.
                if fs::read_dir(&path)?.next().is_none() {
                    let _ = fs::remove_dir(&path);
                }
            } else if is_tree_file(&path) {
                let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                if !keep.contains(&rel) {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }
    rec(root, root, keep)
}

// ---- assemble --------------------------------------------------------------

/// Walks a directory tree back into a [`SessionStore`] with no backing path (it
/// is not saved to disk until [`SessionStore::save_as`]). Sessions always come
/// back without a username.
pub fn assemble(root: &Path) -> Result<SessionStore> {
    let mut acc = Accum::default();
    walk(root, "", &mut acc)?;
    let root_doc = read_folder_doc(&root.join(FOLDER_FILE))?;
    Ok(SessionStore {
        path: PathBuf::new(),
        sessions: acc.sessions,
        folders: acc.folders,
        folder_styles: acc.folder_styles,
        description: root_doc.description,
        icon: root_doc.icon,
        color: root_doc.color,
        name: root_doc.name,
        id: root_doc.id,
        folder_meta: acc.folder_meta,
    })
}

#[derive(Default)]
struct Accum {
    sessions: Vec<Session>,
    folders: Vec<String>,
    folder_styles: BTreeMap<String, FolderStyle>,
    folder_meta: BTreeMap<String, FolderMeta>,
}

fn walk(dir: &Path, display_prefix: &str, acc: &mut Accum) -> Result<()> {
    let mut entries: Vec<fs::DirEntry> = fs::read_dir(dir)
        .with_context(|| format!("could not read {}", dir.display()))?
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("could not read {}", dir.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let ftype = entry.file_type().with_context(|| format!("stat {}", path.display()))?;
        if ftype.is_dir() {
            let doc = read_folder_doc(&path.join(FOLDER_FILE))?;
            let name = if doc.name.is_empty() {
                entry.file_name().to_string_lossy().into_owned()
            } else {
                doc.name.clone()
            };
            let disp = if display_prefix.is_empty() {
                name
            } else {
                format!("{display_prefix}/{name}")
            };
            acc.folders.push(disp.clone());
            let style = FolderStyle { icon: doc.icon.clone(), color: doc.color };
            if !style.is_empty() {
                acc.folder_styles.insert(disp.clone(), style);
            }
            let meta = FolderMeta { id: doc.id.clone(), description: doc.description.clone() };
            if !meta.is_empty() {
                acc.folder_meta.insert(disp.clone(), meta);
            }
            walk(&path, &disp, acc)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some(SESSION_EXT) {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("could not read {}", path.display()))?;
            let doc: SessionDoc = toml::from_str(&text)
                .with_context(|| format!("could not parse {}", path.display()))?;
            acc.sessions.push(doc.into_session(display_prefix.to_owned()));
        }
        // Everything else (the `.folder` sidecar, stray files) is ignored.
    }
    Ok(())
}

/// Reads a `.folder` sidecar, or a default when it is absent.
fn read_folder_doc(path: &Path) -> Result<FolderDoc> {
    match fs::read_to_string(path) {
        Ok(text) => {
            toml::from_str(&text).with_context(|| format!("could not parse {}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FolderDoc::default()),
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
}

// ---- helpers ---------------------------------------------------------------

fn to_toml<T: Serialize>(doc: &T) -> Vec<u8> {
    // These are plain structs of strings/ints/enums; serialization cannot fail.
    toml::to_string_pretty(doc).expect("serializing a tree document").into_bytes()
}

/// Maps each display folder path to a slug directory path, unique among siblings.
/// `folder_paths` must be sorted so parents precede children.
fn slug_paths(folder_paths: &[String]) -> BTreeMap<String, PathBuf> {
    let mut map: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut used: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    for disp in folder_paths {
        let (parent_disp, name) = split_last(disp);
        let parent = if parent_disp.is_empty() {
            PathBuf::new()
        } else {
            map.get(parent_disp).cloned().unwrap_or_default()
        };
        let taken = used.entry(parent.clone()).or_default();
        let slug = unique_slug(&slugify(name), taken);
        taken.insert(slug.clone());
        map.insert(disp.clone(), parent.join(slug));
    }
    map
}

/// Splits `a/b/c` into (`a/b`, `c`); a top-level path into (``, path).
fn split_last(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

/// Lowercase alphanumeric slug, non-alphanumeric runs collapsed to `-`, trimmed.
/// Empty results fall back to `item`.
fn slugify(name: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = true;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() { "item".to_owned() } else { slug }
}

/// A slug not already in `used`; appends `-2`, `-3`, … until free.
fn unique_slug(base: &str, used: &BTreeSet<String>) -> String {
    if !used.contains(base) {
        return base.to_owned();
    }
    (2..).map(|n| format!("{base}-{n}")).find(|c| !used.contains(c)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a store (no backing path) from parts, for tests.
    fn store() -> SessionStore {
        SessionStore {
            name: "Team servers".into(),
            description: "Shared gear".into(),
            icon: "\u{e288}".into(),
            color: Some([10, 20, 30]),
            ..Default::default()
        }
    }

    fn sess(id: &str, name: &str, host: &str, folder: &str) -> Session {
        let mut s = Session::new(name, host, "someuser");
        s.id = id.into();
        s.folder = folder.into();
        s
    }

    fn roundtrip(store: &SessionStore) -> SessionStore {
        let dir = tempfile::tempdir().unwrap();
        write_tree(store, dir.path()).unwrap();
        assemble(dir.path()).unwrap()
    }

    #[test]
    fn roundtrip_preserves_structure() {
        let mut s = store();
        s.sessions.push(sess("a1", "Zone 1", "10.0.0.1", "District/Switches"));
        s.sessions.push(sess("a2", "Root box", "10.0.0.9", ""));
        s.folders.push("District/Switches".into());
        s.folders.push("District/Empty folder".into()); // empty, must persist
        s.folder_styles
            .insert("District/Switches".into(), FolderStyle { icon: "x".into(), color: Some([1, 2, 3]) });
        s.ensure_ids();

        let back = roundtrip(&s);

        assert_eq!(back.name(), "Team servers");
        assert_eq!(back.id(), s.id(), "root id travels");
        assert_eq!(back.description(), "Shared gear");
        assert_eq!(back.icon(), "\u{e288}");
        assert_eq!(back.color(), Some([10, 20, 30]));

        // Sessions (order-independent) with correct folders.
        let z1 = back.get("a1").expect("a1 present");
        assert_eq!(z1.name, "Zone 1");
        assert_eq!(z1.host, "10.0.0.1");
        assert_eq!(z1.folder, "District/Switches");
        let root = back.get("a2").expect("a2 present");
        assert_eq!(root.folder, "");

        // Folders, including the empty one and the implied "District" ancestor.
        let folders = back.folders();
        assert!(folders.contains(&"District".to_owned()), "implied ancestor: {folders:?}");
        assert!(folders.contains(&"District/Switches".to_owned()));
        assert!(folders.contains(&"District/Empty folder".to_owned()), "empty folder persists");

        // Style and folder id survive.
        assert_eq!(back.folder_style("District/Switches").unwrap().color, Some([1, 2, 3]));
        assert_eq!(
            back.folder_meta("District/Switches").map(|m| m.id.clone()),
            s.folder_meta("District/Switches").map(|m| m.id.clone()),
        );
    }

    #[test]
    fn username_is_dropped() {
        let mut s = store();
        let mut sess = sess("u1", "Box", "host", "");
        sess.username = "bob".into();
        s.sessions.push(sess);
        s.ensure_ids();

        let back = roundtrip(&s);
        assert_eq!(back.get("u1").unwrap().username, "", "username must not persist");
    }

    #[test]
    fn vault_reference_is_kept() {
        let mut s = store();
        let mut sess = sess("v1", "Box", "host", "");
        sess.auth = Auth::Vault { entry: "prod-key".into() };
        s.sessions.push(sess);
        s.ensure_ids();

        let back = roundtrip(&s);
        assert_eq!(back.get("v1").unwrap().auth.vault_entry(), Some("prod-key"));
    }

    #[test]
    fn ensure_ids_is_stable() {
        let mut s = store();
        s.folders.push("a/b".into());
        assert!(s.ensure_ids(), "first call assigns");
        let root = s.id().to_owned();
        let a = s.folder_meta("a").unwrap().id.clone();
        let ab = s.folder_meta("a/b").unwrap().id.clone();
        assert!(!s.ensure_ids(), "second call is a no-op");
        assert_eq!(s.id(), root);
        assert_eq!(s.folder_meta("a").unwrap().id, a);
        assert_eq!(s.folder_meta("a/b").unwrap().id, ab);
    }

    #[test]
    fn slug_collisions_stay_distinct() {
        let mut s = store();
        // Both slugify to "prod-db" but must survive as two sessions in one folder.
        s.sessions.push(sess("c1", "Prod DB", "h1", ""));
        s.sessions.push(sess("c2", "prod/db", "h2", ""));
        s.ensure_ids();

        let back = roundtrip(&s);
        assert!(back.get("c1").is_some());
        assert!(back.get("c2").is_some());
        assert_eq!(back.all().len(), 2);
    }

    #[test]
    fn display_names_survive_unslug_friendly_input() {
        let mut s = store();
        s.folders.push("Prod / DB".into()); // a folder name with awkward chars
        s.sessions.push(sess("d1", "Core Switch #3", "h", "Prod / DB"));
        s.ensure_ids();

        let back = roundtrip(&s);
        assert!(back.folders().contains(&"Prod / DB".to_owned()));
        assert_eq!(back.get("d1").unwrap().folder, "Prod / DB");
        assert_eq!(back.get("d1").unwrap().name, "Core Switch #3");
    }

    #[test]
    fn bare_directory_without_sidecar_is_a_folder() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("Loose")).unwrap();
        let back = assemble(dir.path()).unwrap();
        assert!(back.folders().contains(&"Loose".to_owned()));
    }

    #[test]
    fn sync_tree_prunes_removed_items() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store();
        s.sessions.push(sess("x1", "Alpha", "h", "Group"));
        s.sessions.push(sess("x2", "Beta", "h", "Group"));
        s.folders.push("Group".into());
        s.ensure_ids();
        sync_tree(&s, dir.path()).unwrap();
        // root .folder + Group/.folder + two sessions.
        assert_eq!(collect_tree_files(dir.path()).unwrap().len(), 4);

        // Same store minus Beta: re-syncing must delete Beta's file (and nothing else).
        let mut s2 = store();
        s2.id = s.id().to_owned();
        s2.sessions.push(sess("x1", "Alpha", "h", "Group"));
        s2.folders.push("Group".into());
        s2.ensure_ids();
        sync_tree(&s2, dir.path()).unwrap();

        let back = assemble(dir.path()).unwrap();
        assert!(back.get("x1").is_some());
        assert!(back.get("x2").is_none(), "Beta's file should be pruned");
        assert_eq!(collect_tree_files(dir.path()).unwrap().len(), 3);
    }

    #[test]
    fn sync_tree_prunes_emptied_folder_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store();
        s.folders.push("Gone".into());
        s.ensure_ids();
        sync_tree(&s, dir.path()).unwrap();
        assert!(dir.path().join("gone").is_dir());

        // Drop the folder: its directory should be removed, not left dangling.
        let mut s2 = store();
        s2.id = s.id().to_owned();
        s2.ensure_ids();
        sync_tree(&s2, dir.path()).unwrap();
        assert!(!dir.path().join("gone").exists(), "emptied folder dir pruned");
    }

    #[test]
    fn assembles_minimal_handwritten_files() {
        // Guards the format the MobaXterm converter emits: minimal `.folder` /
        // `.wzsession` files (no auth, no username, defaults elsewhere).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".folder"), "id = \"rootid0000000000\"\nname = \"Team\"\n").unwrap();
        std::fs::create_dir_all(root.join("switches")).unwrap();
        std::fs::write(
            root.join("switches/.folder"),
            "id = \"f0000000000000aa\"\nname = \"Switches\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("switches/zone-1.wzsession"),
            "id = \"aaaaaaaaaaaaaaaa\"\nname = \"Zone 1\"\nprotocol = \"ssh\"\n\
             host = \"10.0.0.1\"\nport = 22\n",
        )
        .unwrap();

        let store = assemble(root).unwrap();
        assert_eq!(store.name(), "Team");
        assert_eq!(store.id(), "rootid0000000000");
        assert!(store.folders().contains(&"Switches".to_owned()));
        let s = store.get("aaaaaaaaaaaaaaaa").expect("session present");
        assert_eq!(s.name, "Zone 1");
        assert_eq!(s.folder, "Switches");
        assert_eq!(s.host, "10.0.0.1");
        assert_eq!(s.protocol, Protocol::Ssh);
        assert_eq!(s.auth, Auth::Prompt, "missing auth defaults to prompt");
        assert_eq!(s.username, "", "no username in the file");
    }

    #[test]
    fn copy_tree_mirrors_then_prunes() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let mut s = store();
        s.sessions.push(sess("m1", "One", "h", ""));
        s.sessions.push(sess("m2", "Two", "h", ""));
        s.ensure_ids();
        sync_tree(&s, a.path()).unwrap();
        copy_tree(a.path(), b.path()).unwrap();
        assert_eq!(assemble(b.path()).unwrap().all().len(), 2);

        // Shrink the source, re-mirror: the mirror drops the removed file too.
        let mut s2 = store();
        s2.id = s.id().to_owned();
        s2.sessions.push(sess("m1", "One", "h", ""));
        s2.ensure_ids();
        sync_tree(&s2, a.path()).unwrap();
        copy_tree(a.path(), b.path()).unwrap();
        let back = assemble(b.path()).unwrap();
        assert!(back.get("m1").is_some());
        assert!(back.get("m2").is_none(), "mirror should prune the removed session");
    }
}
