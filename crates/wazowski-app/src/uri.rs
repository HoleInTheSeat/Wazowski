//! Parsing and hand-off for connection URIs (`ssh://`, `telnet://`).
//!
//! A browser (or any app) can open `ssh://user@host:port` or `telnet://host`;
//! both are treated as SSH. Wazowski either connects a matching saved session or
//! falls back to a quick-connect prompt. When an instance is already running, the
//! URI is dropped into an "inbox" directory that the running instance watches, so
//! the connection opens in the existing window instead of a second one.

use std::path::PathBuf;

/// A parsed connection URI. Protocol is always SSH (telnet is treated as SSH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUri {
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
}

/// Whether `s` is a connection URI Wazowski handles.
pub fn is_connect_uri(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("ssh://") || l.starts_with("telnet://")
}

/// Parses `ssh://[user@]host[:port][/…]` or `telnet://…` (both SSH). Supports a
/// bracketed IPv6 host (`ssh://[::1]:22`). Returns `None` if not a handled URI or
/// the host is missing.
pub fn parse_connect_uri(s: &str) -> Option<ConnectUri> {
    let s = s.trim();
    let rest = strip_scheme(s, "ssh://").or_else(|| strip_scheme(s, "telnet://"))?;
    // The authority is everything up to the first path/query/fragment separator.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    // Optional "user@".
    let (user, hostport) = match authority.rsplit_once('@') {
        Some((u, hp)) => (Some(percent_decode(u)), hp),
        None => (None, authority),
    };
    let (host, port) = split_host_port(hostport)?;
    if host.is_empty() {
        return None;
    }
    Some(ConnectUri { host, port, user: user.filter(|u| !u.is_empty()) })
}

/// Case-insensitively strips a scheme prefix.
fn strip_scheme<'a>(s: &'a str, scheme: &str) -> Option<&'a str> {
    (s.len() >= scheme.len() && s[..scheme.len()].eq_ignore_ascii_case(scheme))
        .then(|| &s[scheme.len()..])
}

/// Splits `host[:port]`, honouring a bracketed IPv6 literal.
fn split_host_port(hostport: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        // [ipv6] optionally followed by :port
        let (h, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
        Some((h.to_string(), port))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => Some((h.to_string(), Some(port))),
                // A colon that isn't a port (unusual) — treat the whole thing as host.
                Err(_) => Some((hostport.to_string(), None)),
            },
            None => Some((hostport.to_string(), None)),
        }
    }
}

/// Minimal percent-decoding for the userinfo component.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The directory a second instance drops incoming URIs into for the running one.
pub fn inbox_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("org", "wazowski", "wazowski")
        .map(|d| d.config_dir().join("uri-inbox"))
}

/// Writes `uri` to the inbox for a running instance to pick up.
pub fn write_to_inbox(uri: &str) -> std::io::Result<()> {
    let dir = inbox_dir()
        .ok_or_else(|| std::io::Error::other("could not determine the config directory"))?;
    std::fs::create_dir_all(&dir)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = format!("{}-{}.uri", std::process::id(), nanos);
    std::fs::write(dir.join(name), uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_and_telnet_as_ssh() {
        assert!(is_connect_uri("ssh://host"));
        assert!(is_connect_uri("TELNET://host"));
        assert!(!is_connect_uri("http://host"));

        let u = parse_connect_uri("ssh://root@10.0.0.5:2222").unwrap();
        assert_eq!(u.host, "10.0.0.5");
        assert_eq!(u.port, Some(2222));
        assert_eq!(u.user.as_deref(), Some("root"));

        // telnet is treated the same (host only).
        let t = parse_connect_uri("telnet://192.168.72.205").unwrap();
        assert_eq!(t.host, "192.168.72.205");
        assert_eq!(t.port, None);
        assert_eq!(t.user, None);
    }

    #[test]
    fn handles_path_ipv6_and_encoding() {
        let p = parse_connect_uri("ssh://me@box.lan/some/path?x=1").unwrap();
        assert_eq!(p.host, "box.lan");
        assert_eq!(p.user.as_deref(), Some("me"));

        let v6 = parse_connect_uri("ssh://[2001:db8::1]:22").unwrap();
        assert_eq!(v6.host, "2001:db8::1");
        assert_eq!(v6.port, Some(22));

        let enc = parse_connect_uri("ssh://first%20last@host").unwrap();
        assert_eq!(enc.user.as_deref(), Some("first last"));
    }

    #[test]
    fn rejects_non_connect_and_empty() {
        assert!(parse_connect_uri("http://host").is_none());
        assert!(parse_connect_uri("ssh://").is_none());
        assert!(parse_connect_uri("ssh:///path").is_none());
    }
}
