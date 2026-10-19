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
fn ping(ip: IpAddr) -> bool {
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

/// Pings a single host off the UI thread, resolving it first. The streamed
/// message is a human-readable status line.
pub fn ping_host(host: String) -> ScanHandle<String> {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let d = done.clone();
    thread::spawn(move || {
        let msg = match resolve(&host) {
            None => format!("Could not resolve {host}"),
            Some(ip) => {
                if ping(ip) {
                    format!("{host} ({ip}) is up")
                } else {
                    format!("{host} ({ip}) did not reply")
                }
            }
        };
        let _ = tx.send(msg);
        d.store(true, Ordering::Relaxed);
    });
    ScanHandle { rx, cancel, done }
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
                    let pingable = ping(IpAddr::V4(ip));
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


// ─── Web/API tools ──────────────────────────────────────────────────────────

/// A one-shot background job whose single result is polled from the UI thread.
pub struct Job<T> {
    rx: Receiver<T>,
}

impl<T> Job<T> {
    /// Returns the result once the job finishes, else `None`.
    pub fn poll(&self) -> Option<T> {
        self.rx.try_recv().ok()
    }
}

/// Runs `f` on a worker thread; its return value is delivered to [`Job::poll`].
pub fn spawn_job<T, F>(f: F) -> Job<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    Job { rx }
}

/// An HTTP request issued by the API tool.
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// An HTTP response shown by the API tool.
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

fn into_response(resp: ureq::Response) -> HttpResponse {
    let status = resp.status();
    let status_text = resp.status_text().to_owned();
    let headers = resp
        .headers_names()
        .iter()
        .filter_map(|n| resp.header(n).map(|v| (n.clone(), v.to_owned())))
        .collect();
    let body = resp.into_string().unwrap_or_default();
    HttpResponse { status, status_text, headers, body }
}

/// Performs a blocking HTTP request. Non-2xx responses are returned as `Ok`
/// (with their status and body) so the UI can display them; only transport
/// errors become `Err`.
pub fn http_fetch(req: HttpRequest) -> Result<HttpResponse, String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(30)).build();
    let mut r = agent.request(&req.method, &req.url);
    for (k, v) in &req.headers {
        r = r.set(k, v);
    }
    let result = match &req.body {
        Some(b) if !b.is_empty() => r.send_string(b),
        _ => r.call(),
    };
    match result {
        Ok(resp) => Ok(into_response(resp)),
        Err(ureq::Error::Status(_, resp)) => Ok(into_response(resp)),
        Err(e) => Err(e.to_string()),
    }
}

/// Looks up this machine's public IP via api.ipify.org (an external query).
pub fn public_ip() -> Result<String, String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).build();
    agent
        .get("https://api.ipify.org")
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map(|s| s.trim().to_owned())
        .map_err(|e| e.to_string())
}

/// Filters `json` through the system `jq` with `filter` (uses `-r` so scalar
/// results come out raw). Requires `jq` on the PATH.
pub fn jq_filter(json: &str, filter: &str) -> Result<String, String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut cmd = Command::new("jq");
    cmd.arg("-r").arg(filter).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    hide_window(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Could not run jq (is it installed? — see Settings ▸ Extras): {e}"))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let owned = json.to_owned();
    let writer = thread::spawn(move || {
        let _ = stdin.write_all(owned.as_bytes());
    });
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let _ = writer.join();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// Pretty-prints JSON; returns the input unchanged if it isn't valid JSON.
pub fn pretty_json(text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| serde_json::to_string_pretty(&v).ok())
        .unwrap_or_else(|| text.to_owned())
}

/// One local interface address.
pub struct IfaceAddr {
    pub name: String,
    pub ip: String,
    pub prefix: u8,
}

/// This host's addressing, for the IP Address Viewer.
pub struct IpInfo {
    pub interfaces: Vec<IfaceAddr>,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
    pub domain: Option<String>,
}

/// Gathers local addressing (interfaces via the OS; gateway/DNS/domain on Linux
/// via `ip route` and `/etc/resolv.conf`; best-effort elsewhere).
pub fn ip_info() -> IpInfo {
    let mut interfaces = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            let (ip, prefix) = match iface.addr {
                if_addrs::IfAddr::V4(v4) => {
                    (v4.ip.to_string(), u32::from(v4.netmask).count_ones() as u8)
                }
                if_addrs::IfAddr::V6(v6) => {
                    (v6.ip.to_string(), u128::from(v6.netmask).count_ones() as u8)
                }
            };
            interfaces.push(IfaceAddr { name: iface.name, ip, prefix });
        }
    }
    let (dns, domain) = resolv_conf();
    IpInfo { interfaces, gateway: default_gateway(), dns, domain }
}

/// Parses the default gateway from `ip route show default` (Linux).
fn default_gateway() -> Option<String> {
    let mut cmd = Command::new("ip");
    cmd.args(["route", "show", "default"]);
    hide_window(&mut cmd);
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut tokens = text.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "via" {
            return tokens.next().map(str::to_owned);
        }
    }
    None
}

/// Reads nameservers and the search/domain from `/etc/resolv.conf` (Linux).
fn resolv_conf() -> (Vec<String>, Option<String>) {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut dns = Vec::new();
    let mut domain = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(ns) = line.strip_prefix("nameserver ") {
            dns.push(ns.trim().to_owned());
        } else if let Some(d) = line.strip_prefix("domain ") {
            domain = Some(d.trim().to_owned());
        } else if let Some(s) = line.strip_prefix("search ")
            && domain.is_none()
        {
            domain = Some(s.split_whitespace().next().unwrap_or("").to_owned());
        }
    }
    (dns, domain)
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
