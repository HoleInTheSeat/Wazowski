//! A small network toolbox: port scanner, subnet (ping + service) scanner,
//! local listening ports, and Wake-on-LAN. Scans run on worker threads and
//! stream results back over a channel so the UI stays responsive.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

/// Stops a spawned helper (ping/ss) from flashing a console window on Windows.
#[cfg(windows)]
fn hide_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}
#[cfg(not(windows))]
fn hide_window(_cmd: &mut Command) {}

/// Well-known ports and their service labels, for the "common" scan and for
/// naming open ports in results.
pub const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (67, "dhcp"),
    (80, "http"),
    (110, "pop3"),
    (111, "rpcbind"),
    (123, "ntp"),
    (135, "msrpc"),
    (139, "netbios"),
    (143, "imap"),
    (161, "snmp"),
    (389, "ldap"),
    (443, "https"),
    (445, "smb"),
    (514, "syslog"),
    (587, "smtp"),
    (631, "ipp"),
    (993, "imaps"),
    (995, "pop3s"),
    (1433, "mssql"),
    (1521, "oracle"),
    (2049, "nfs"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5060, "sip"),
    (5432, "postgres"),
    (5900, "vnc"),
    (5985, "winrm"),
    (6379, "redis"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (9100, "jetdirect"),
];

/// The small set probed to detect services during a subnet scan (MobaXterm-style).
pub const SERVICE_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (80, "http"),
    (443, "https"),
    (445, "smb"),
    (3389, "rdp"),
    (5900, "vnc"),
];

/// The service label for a port, or an empty string.
pub fn service_name(port: u16) -> &'static str {
    COMMON_PORTS.iter().find(|(p, _)| *p == port).map(|(_, n)| *n).unwrap_or("")
}

/// A running scan: results stream over `rx`; `done` flips when it finishes.
pub struct ScanHandle<T> {
    rx: Receiver<T>,
    cancel: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

impl<T> ScanHandle<T> {
    pub fn drain(&self) -> Vec<T> {
        self.rx.try_iter().collect()
    }

    pub fn running(&self) -> bool {
        !self.done.load(Ordering::Relaxed)
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl<T> Drop for ScanHandle<T> {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// An open port found by a scan.
pub struct PortHit {
    pub port: u16,
    pub service: &'static str,
}

/// A host found by a subnet scan.
pub struct HostHit {
    pub ip: Ipv4Addr,
    pub pingable: bool,
    pub services: Vec<(u16, &'static str)>,
}

/// Resolves a host/IP string to an address, via parse then DNS.
pub fn resolve(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    (host, 0u16).to_socket_addrs().ok()?.next().map(|s| s.ip())
}

/// Parses a port spec like `22,80,443` or `1-1024` (ranges and lists mixed).
pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                ports.extend(a.min(b)..=a.max(b));
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Parses `a.b.c.d/nn` into its host addresses (network/broadcast excluded for
/// prefixes up to /30). Capped to 65536 addresses.
pub fn parse_cidr(spec: &str) -> Option<Vec<Ipv4Addr>> {
    let (addr, prefix) = spec.split_once('/')?;
    let base: Ipv4Addr = addr.trim().parse().ok()?;
    let prefix: u32 = prefix.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let base_u = u32::from(base);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = base_u & mask;
    let count = 1u64 << (32 - prefix);
    if count > 65_536 {
        return None;
    }
    let (first, last) = if prefix <= 30 {
        (network + 1, network + count as u32 - 1) // skip network & broadcast
    } else {
        (network, network + count as u32) // /31, /32: include all
    };
    Some((first..last).map(Ipv4Addr::from).collect())
}

/// Tries to open a TCP connection, returning whether it succeeded.
fn port_open(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout).is_ok()
}

/// Splits `items` into at most `workers` chunks for parallel scanning.
fn chunk<T: Clone>(items: &[T], workers: usize) -> Vec<Vec<T>> {
    let workers = workers.clamp(1, items.len().max(1));
    let mut chunks = vec![Vec::new(); workers];
    for (i, item) in items.iter().enumerate() {
        chunks[i % workers].push(item.clone());
    }
    chunks
}

/// Scans `ports` on `ip`, streaming each open port back.
pub fn scan_ports(ip: IpAddr, ports: Vec<u16>, timeout: Duration) -> ScanHandle<PortHit> {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let chunks = chunk(&ports, 128);
    let (c, d) = (cancel.clone(), done.clone());
    thread::spawn(move || {
        let mut handles = Vec::new();
        for chunk in chunks {
            let (tx, cancel) = (tx.clone(), c.clone());
            handles.push(thread::spawn(move || {
                for port in chunk {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    if port_open(ip, port, timeout) {
                        let _ = tx.send(PortHit { port, service: service_name(port) });
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        d.store(true, Ordering::Relaxed);
    });
    ScanHandle { rx, cancel, done }
}

/// Whether `ip` answers a single ICMP echo (via the system `ping`).
fn ping(ip: Ipv4Addr) -> bool {
    let ip = ip.to_string();
    let mut cmd = Command::new("ping");
    #[cfg(windows)]
    cmd.args(["-n", "1", "-w", "1000", &ip]);
    #[cfg(not(windows))]
    cmd.args(["-c", "1", "-W", "1", &ip]);
    hide_window(&mut cmd);
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Pings each host and probes common service ports, streaming reachable hosts.
pub fn scan_subnet(hosts: Vec<Ipv4Addr>, timeout: Duration) -> ScanHandle<HostHit> {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let chunks = chunk(&hosts, 64);
    let (c, d) = (cancel.clone(), done.clone());
    thread::spawn(move || {
        let mut handles = Vec::new();
        for chunk in chunks {
            let (tx, cancel) = (tx.clone(), c.clone());
            handles.push(thread::spawn(move || {
                for ip in chunk {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let pingable = ping(ip);
                    let services: Vec<(u16, &'static str)> = SERVICE_PORTS
                        .iter()
                        .filter(|(p, _)| port_open(IpAddr::V4(ip), *p, timeout))
                        .copied()
                        .collect();
                    if pingable || !services.is_empty() {
                        let _ = tx.send(HostHit { ip, pingable, services });
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        d.store(true, Ordering::Relaxed);
    });
    ScanHandle { rx, cancel, done }
}

/// A listening socket on the local host.
pub struct LocalPort {
    pub proto: String,
    pub address: String,
    pub process: String,
}

/// Lists the host's listening TCP/UDP sockets via `ss` (Linux) or `netstat`.
pub fn local_listening_ports() -> Result<Vec<LocalPort>, String> {
    let mut ss = Command::new("ss");
    ss.args(["-tulnpH"]);
    hide_window(&mut ss);
    let output = ss
        .output()
        .or_else(|_| {
            let mut ns = Command::new("netstat");
            ns.args(["-tulnp"]);
            hide_window(&mut ns);
            ns.output()
        })
        .map_err(|e| format!("could not list ports (need `ss` or `netstat`): {e}"))?;
    if !output.status.success() {
        return Err("the port-listing command failed".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut ports = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // ss -tulnH columns: Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]
        if cols.len() < 5 {
            continue;
        }
        let proto = cols[0].to_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        let address = cols[4].to_owned();
        let process = cols
            .get(6)
            .or_else(|| cols.get(5))
            .map(|s| parse_process(s))
            .unwrap_or_default();
        ports.push(LocalPort { proto, address, process });
    }
    ports.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(ports)
}

/// Pulls a readable process name out of `ss`'s `users:(("name",pid=…))` field.
fn parse_process(field: &str) -> String {
    field
        .split_once("((\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(name, _)| name.to_owned())
        .unwrap_or_default()
}

/// Parses a MAC address written with `:`, `-`, or `.` separators (or none).
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(mac)
}

/// Sends a Wake-on-LAN magic packet for `mac` to the broadcast address.
pub fn send_wol(mac: [u8; 6]) -> Result<(), String> {
    let mut packet = vec![0xffu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("socket error: {e}"))?;
    socket.set_broadcast(true).map_err(|e| format!("broadcast error: {e}"))?;
    socket
        .send_to(&packet, "255.255.255.255:9")
        .map_err(|e| format!("send failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ports() {
        assert_eq!(parse_ports("22, 80,443"), vec![22, 80, 443]);
        assert_eq!(parse_ports("20-22"), vec![20, 21, 22]);
        assert_eq!(parse_ports("443,443,80"), vec![80, 443]);
    }

    #[test]
    fn parses_cidr() {
        let hosts = parse_cidr("10.0.0.0/24").unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(10, 0, 0, 254));
        assert!(parse_cidr("10.0.0.0/8").is_none()); // too large
    }

    #[test]
    fn parses_mac() {
        let expected = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF"), Some(expected));
        assert_eq!(parse_mac("aa-bb-cc-dd-ee-ff"), Some(expected));
        assert_eq!(parse_mac("aabb.ccdd.eeff"), Some(expected));
        assert_eq!(parse_mac("nope"), None);
    }
}
