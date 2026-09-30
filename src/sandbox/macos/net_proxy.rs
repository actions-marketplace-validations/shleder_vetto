#![cfg(target_os = "macos")]

//! macOS local broker/proxy primitives for pinned outbound connections.
//!
//! DNS resolution happens in the broker process, not in the sandboxed child.
//! Every permitted connection stores the resulting `SocketAddr` and connects
//! to that address directly, preventing a second resolver lookup at connect
//! time.  Private, loopback, link-local, metadata, documentation, and NAT64
//! translation addresses are rejected for both IPv4 and IPv6.  This module is
//! a TCP pass-through helper: it never performs TLS MITM or certificate
//! substitution.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::config::NetMode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedConnection {
    host: String,
    port: u16,
    addr: SocketAddr,
}

impl PinnedConnection {
    /// Connect to the already-pinned address.  No hostname is passed to the
    /// socket API, so DNS cannot be re-resolved after policy authorization.
    pub fn connect(&self, timeout: Option<Duration>) -> io::Result<TcpStream> {
        if self.port == 0 || self.addr.port() != self.port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pinned connection port does not match its SocketAddr",
            ));
        }
        if normalize_host(&self.host).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid pinned host",
            ));
        }
        validate_public_addr(self.addr.ip())
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        let stream = match timeout {
            Some(timeout) => TcpStream::connect_timeout(&self.addr, timeout)?,
            None => TcpStream::connect(self.addr)?,
        };
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

#[derive(Clone, Debug)]
pub struct BrokerPolicy {
    mode: NetMode,
    bind: SocketAddr,
}

impl BrokerPolicy {
    pub fn new(mode: NetMode, bind: SocketAddr) -> Result<Self> {
        if !is_loopback(bind.ip()) {
            bail!("local broker must bind to loopback, not {}", bind.ip());
        }
        if matches!(&mode, &NetMode::Off) {
            bail!("a broker policy cannot be constructed for --net=off");
        }
        Ok(Self { mode, bind })
    }

    pub fn authorize(&self, host: &str, port: u16, addr: SocketAddr) -> Result<PinnedConnection> {
        let host = normalize_host(host)?;
        if port == 0 || addr.port() != port {
            bail!("pinned endpoint port does not match the requested port");
        }
        validate_public_addr(addr.ip())?;
        match &self.mode {
            NetMode::Off => bail!("network policy is off"),
            NetMode::Allowlist(domains) => {
                if !domains.iter().any(|domain| host_matches(&host, domain)) {
                    bail!("host {host:?} is not in the broker allowlist");
                }
            }
            NetMode::Strict(rules) => {
                if !rules
                    .iter()
                    .any(|rule| rule.port == port && host_matches(&host, &rule.domain))
                {
                    bail!("host {host:?}:{port} is not in the strict broker policy");
                }
            }
            NetMode::Ask => {}
        }
        Ok(PinnedConnection { host, port, addr })
    }

    /// Resolve and authorize in the broker.  The returned addresses are the
    /// only addresses this policy permits the caller to connect to.
    pub fn resolve(&self, host: &str, port: u16) -> Result<Vec<PinnedConnection>> {
        let normalized = normalize_host(host)?;
        if port == 0 {
            bail!("port 0 is not a connectable broker target");
        }
        match &self.mode {
            NetMode::Off => bail!("network policy is off"),
            NetMode::Allowlist(domains) => {
                if !domains
                    .iter()
                    .any(|domain| host_matches(&normalized, domain))
                {
                    bail!("host {normalized:?} is not in the broker allowlist");
                }
            }
            NetMode::Strict(rules) => {
                if !rules
                    .iter()
                    .any(|rule| rule.port == port && host_matches(&normalized, &rule.domain))
                {
                    bail!("host {normalized:?}:{port} is not in the strict broker policy");
                }
            }
            NetMode::Ask => {}
        }
        let mut addresses = (normalized.as_str(), port)
            .to_socket_addrs()
            .with_context(|| format!("resolve {normalized}:{port} in broker"))?
            .collect::<Vec<_>>();
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            bail!("resolver returned no addresses for {normalized}:{port}");
        }
        if addresses.len() > 1024 {
            bail!("resolver returned too many addresses for {normalized}:{port}");
        }
        let mut pinned = Vec::with_capacity(addresses.len());
        for addr in addresses {
            pinned.push(self.authorize(&normalized, port, addr)?);
        }
        Ok(pinned)
    }

    pub fn mode(&self) -> &NetMode {
        &self.mode
    }

    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind
    }
}

/// A loopback listener owned by the broker.  It does not proxy transparently
/// by itself; callers accept child connections and use `BrokerPolicy::resolve`
/// plus `PinnedConnection::connect` for the outbound side.
pub struct LocalBroker {
    listener: TcpListener,
    policy: BrokerPolicy,
}

impl std::fmt::Debug for LocalBroker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalBroker")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("policy", &self.policy)
            .field("tls", &"passthrough; no MITM")
            .finish()
    }
}

impl LocalBroker {
    pub fn bind(policy: BrokerPolicy) -> Result<Self> {
        let listener = TcpListener::bind(policy.bind)
            .with_context(|| format!("bind local broker at {}", policy.bind))?;
        let bound = listener.local_addr()?;
        if !is_loopback(bound.ip()) {
            bail!("OS returned a non-loopback broker address {bound}");
        }
        Ok(Self { listener, policy })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.listener.accept()
    }

    pub fn policy(&self) -> &BrokerPolicy {
        &self.policy
    }

    pub const fn tls_mode() -> &'static str {
        "TLS pass-through only; no certificate interception or MITM"
    }

    /// Start the broker accept loop in a background supervisor thread.
    pub fn start(self) -> Result<LocalBrokerHandle> {
        let port = self.local_addr()?.port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let listener = self.listener;
        let policy = self.policy;

        let thread = std::thread::Builder::new()
            .name("vetto-macos-proxy".into())
            .spawn(move || {
                while !shutdown_clone.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _addr)) => {
                            if shutdown_clone.load(Ordering::SeqCst) {
                                break;
                            }
                            let policy_clone = policy.clone();
                            let _ = std::thread::Builder::new()
                                .name("vetto-macos-proxy-worker".into())
                                .spawn(move || {
                                    handle_client(stream, &policy_clone);
                                });
                        }
                        Err(_) => {
                            if shutdown_clone.load(Ordering::SeqCst) {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })
            .context("spawn macos local broker thread")?;

        Ok(LocalBrokerHandle {
            shutdown,
            port,
            thread: Some(thread),
        })
    }
}

pub struct LocalBrokerHandle {
    shutdown: Arc<AtomicBool>,
    port: u16,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LocalBrokerHandle {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }

    pub fn join(mut self) -> std::thread::Result<()> {
        if let Some(thread) = self.thread.take() {
            thread.join()
        } else {
            Ok(())
        }
    }
}

/// Construct proxy environment variables pointing to the local broker.
pub fn build_proxy_env(port: u16) -> Vec<(String, String)> {
    let proxy_url = format!("http://127.0.0.1:{port}");
    vec![
        ("HTTP_PROXY".to_string(), proxy_url.clone()),
        ("HTTPS_PROXY".to_string(), proxy_url.clone()),
        ("ALL_PROXY".to_string(), proxy_url.clone()),
        ("http_proxy".to_string(), proxy_url.clone()),
        ("https_proxy".to_string(), proxy_url.clone()),
        ("all_proxy".to_string(), proxy_url),
        ("NO_PROXY".to_string(), String::new()),
        ("no_proxy".to_string(), String::new()),
    ]
}

fn handle_client(mut client: TcpStream, policy: &BrokerPolicy) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = client.set_nodelay(true);

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    let n = match client.read(&mut chunk) {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    buf.extend_from_slice(&chunk[..n]);

    if buf[0] == 0x16 {
        handle_tls_client(client, buf, policy);
    } else {
        handle_http_client(client, buf, policy);
    }
}

fn handle_tls_client(mut client: TcpStream, mut buf: Vec<u8>, policy: &BrokerPolicy) {
    const MAX_TLS_HELLO: usize = 16 * 1024;
    let mut sni = extract_client_hello_sni(&buf);
    while sni.is_none() && buf.len() < MAX_TLS_HELLO {
        if buf.len() >= 5 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= 5 + record_len {
                break;
            }
        }
        let mut chunk = [0u8; 1024];
        match client.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                sni = extract_client_hello_sni(&buf);
            }
        }
    }

    let Some(host) = sni else {
        return;
    };

    let pinned = match policy.resolve(&host, 443) {
        Ok(p) => p,
        Err(_) => return,
    };

    let mut outbound = match pinned[0].connect(Some(Duration::from_secs(10))) {
        Ok(s) => s,
        Err(_) => return,
    };

    if outbound.write_all(&buf).is_err() {
        return;
    }

    tunnel(client, outbound);
}

fn handle_http_client(mut client: TcpStream, mut buf: Vec<u8>, policy: &BrokerPolicy) {
    const MAX_HTTP_HEAD: usize = 32 * 1024;
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < MAX_HTTP_HEAD {
        let mut chunk = [0u8; 1024];
        match client.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }

    let header_end = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => pos + 4,
        None => return,
    };

    let head_str = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut lines = head_str.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => return,
    };

    let mut parts = request_line.split_whitespace();
    let method = match parts.next() {
        Some(m) => m.to_ascii_uppercase(),
        None => return,
    };

    let target = match parts.next() {
        Some(t) => t,
        None => return,
    };

    if method == "CONNECT" {
        let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
            let port: u16 = match p.parse() {
                Ok(p) => p,
                Err(_) => {
                    let _ =
                        client.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                    return;
                }
            };
            (h, port)
        } else {
            (target, 443)
        };

        let pinned = match policy.resolve(host, port) {
            Ok(p) => p,
            Err(_) => {
                let _ = client.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nAccess denied by Vetto policy\r\n",
                );
                return;
            }
        };

        let mut outbound = match pinned[0].connect(Some(Duration::from_secs(10))) {
            Ok(s) => s,
            Err(_) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                return;
            }
        };

        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }

        if buf.len() > header_end && outbound.write_all(&buf[header_end..]).is_err() {
            return;
        }

        tunnel(client, outbound);
    } else {
        let (host, port, path) = if let Some(stripped) = target.strip_prefix("http://") {
            let (authority, path) = match stripped.split_once('/') {
                Some((a, p)) => (a, format!("/{p}")),
                None => (stripped, "/".to_string()),
            };
            let (h, p) = if let Some((h, p)) = authority.rsplit_once(':') {
                (h, p.parse::<u16>().unwrap_or(80))
            } else {
                (authority, 80)
            };
            (h, p, path)
        } else {
            let mut host_header = None;
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("host") {
                        host_header = Some(v.trim());
                        break;
                    }
                }
            }
            let authority = match host_header {
                Some(a) => a,
                None => {
                    let _ = client.write_all(
                        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nMissing Host header\r\n",
                    );
                    return;
                }
            };
            let (h, p) = if let Some((h, p)) = authority.rsplit_once(':') {
                (h, p.parse::<u16>().unwrap_or(80))
            } else {
                (authority, 80)
            };
            (h, p, target.to_string())
        };

        let pinned = match policy.resolve(host, port) {
            Ok(p) => p,
            Err(_) => {
                let _ = client.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nAccess denied by Vetto policy\r\n",
                );
                return;
            }
        };

        let mut outbound = match pinned[0].connect(Some(Duration::from_secs(10))) {
            Ok(s) => s,
            Err(_) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                return;
            }
        };

        let mut rewritten_head = format!("{method} {path} HTTP/1.1\r\n");
        if let Some(pos) = head_str.find("\r\n") {
            rewritten_head.push_str(&head_str[pos + 2..]);
        }

        if outbound.write_all(rewritten_head.as_bytes()).is_err() {
            return;
        }

        if buf.len() > header_end && outbound.write_all(&buf[header_end..]).is_err() {
            return;
        }

        tunnel(client, outbound);
    }
}

fn tunnel(client: TcpStream, outbound: TcpStream) {
    let _ = client.set_nodelay(true);
    let _ = outbound.set_nodelay(true);
    let _ = client.set_read_timeout(None);
    let _ = outbound.set_read_timeout(None);

    let mut client_read = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut client_write = client;
    let mut outbound_read = match outbound.try_clone() {
        Ok(o) => o,
        Err(_) => return,
    };
    let mut outbound_write = outbound;

    let t1 = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut outbound_write);
        let _ = outbound_write.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut outbound_read, &mut client_write);
    let _ = client_write.shutdown(std::net::Shutdown::Write);
    let _ = t1.join();
}

pub fn extract_client_hello_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }
    if buf[5] != 0x01 {
        return None;
    }
    let handshake_len = u32::from_be_bytes([0, buf[6], buf[7], buf[8]]) as usize;
    if record_len < 4 + handshake_len {
        return None;
    }

    let mut pos = 9 + 2 + 32;
    if pos >= buf.len() {
        return None;
    }
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > buf.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos >= buf.len() {
        return None;
    }
    let comp_methods_len = buf[pos] as usize;
    pos += 1 + comp_methods_len;

    if pos + 2 > buf.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + extensions_len;
    if ext_end > buf.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            if pos + ext_len > ext_end || ext_len < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            let mut sni_pos = pos + 2;
            let list_end = pos + 2 + list_len;
            if list_end > pos + ext_len {
                return None;
            }

            while sni_pos + 3 <= list_end {
                let name_type = buf[sni_pos];
                let name_len = u16::from_be_bytes([buf[sni_pos + 1], buf[sni_pos + 2]]) as usize;
                sni_pos += 3;
                if name_type == 0 && sni_pos + name_len <= list_end {
                    let host = std::str::from_utf8(&buf[sni_pos..sni_pos + name_len]).ok()?;
                    return Some(host.to_string());
                }
                sni_pos += name_len;
            }
        }
        pos += ext_len;
    }
    None
}

pub fn validate_public_addr(addr: IpAddr) -> Result<()> {
    if is_restricted_addr(addr) {
        bail!("refusing private, loopback, metadata, documentation, or NAT64 address {addr}");
    }
    Ok(())
}

fn strip_domain_port(s: &str) -> &str {
    let s = s.trim().trim_end_matches('.');
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end_bracket) = rest.find(']') {
            &rest[..end_bracket]
        } else {
            s
        }
    } else if let Some((host_part, port_part)) = s.rsplit_once(':') {
        if !port_part.is_empty()
            && port_part.chars().all(|c| c.is_ascii_digit())
            && !host_part.contains(':')
        {
            host_part
        } else {
            s
        }
    } else {
        s
    }
}

fn normalize_host(host: &str) -> Result<String> {
    let host = strip_domain_port(host);
    if host.is_empty() || host.contains('\0') || host.chars().any(char::is_whitespace) {
        bail!("host is empty, contains NUL, or contains whitespace");
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('@') || host.contains('/') || host.contains('\\') {
        bail!("host contains unsupported URL/userinfo syntax");
    }
    if host.len() > 253 || host.parse::<IpAddr>().is_ok() || !host.is_ascii() {
        bail!("host must be an ASCII DNS name, not an IP literal");
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|character| character.is_ascii_alphanumeric() || character == b'-')
        {
            bail!("host contains an invalid DNS label");
        }
    }
    Ok(host)
}

fn host_matches(host: &str, configured: &str) -> bool {
    let configured_clean = strip_domain_port(configured);
    let (is_wildcard, clean_target) = if let Some(suffix) = configured_clean.strip_prefix("*.") {
        (true, suffix)
    } else {
        (false, configured_clean)
    };
    let Ok(configured) = normalize_host(clean_target) else {
        return false;
    };
    let host = strip_domain_port(host).to_ascii_lowercase();
    if is_wildcard {
        host.ends_with(&format!(".{configured}"))
    } else {
        host == configured || host.ends_with(&format!(".{configured}"))
    }
}

fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(value) => value.is_loopback(),
        IpAddr::V6(value) => value.is_loopback(),
    }
}

fn is_restricted_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(value) => is_restricted_v4(value),
        IpAddr::V6(value) => is_restricted_v6(value),
    }
}

fn is_restricted_v4(value: Ipv4Addr) -> bool {
    let octets = value.octets();
    let first = octets[0];
    let second = octets[1];
    let third = octets[2];
    let fourth = octets[3];
    value.is_unspecified()
        || value.is_loopback()
        || value.is_private()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_broadcast()
        || (first == 0)
        || (first == 100 && (64..=127).contains(&second)) // RFC 6598 CGNAT
        || (first == 169 && second == 254) // link-local and cloud metadata
        || (first == 192 && second == 0 && third == 0) // IETF protocol assignments
        || (first == 192 && second == 0 && third == 2) // TEST-NET-1
        || (first == 198 && second == 18) // benchmarking
        || (first == 198 && second == 19)
        || (first == 198 && second == 51 && third == 100) // TEST-NET-2
        || (first == 203 && second == 0 && third == 113) // TEST-NET-3
        || (first == 192 && second == 88 && third == 99) // 6to4 anycast
        || (first == 169 && second == 254 && third == 169 && fourth == 254)
}

fn is_restricted_v6(value: Ipv6Addr) -> bool {
    let segments = value.segments();
    let mapped_v4 = if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ))
    } else if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        // IPv4-compatible and IPv4-translated forms should not bypass the
        // IPv4 policy by arriving as IPv6 literals.
        Some(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ))
    } else {
        None
    };
    value.is_unspecified()
        || value.is_loopback()
        || value.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00 // ULA/private
        || (segments[0] & 0xffc0) == 0xfe80 // link-local
        || segments[0] == 0x2001 && segments[1] == 0x0db8 // documentation
        || (segments[0] == 0x0064 && segments[1] == 0xff9b) // RFC 6052 NAT64
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1)
        || mapped_v4.is_some_and(is_restricted_v4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_metadata_and_nat64_are_rejected() {
        for address in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V6("fd00::1".parse().unwrap()),
            IpAddr::V6("64:ff9b::c000:0201".parse().unwrap()),
        ] {
            assert!(validate_public_addr(address).is_err(), "{address}");
        }
    }

    #[test]
    fn policy_pins_the_supplied_socket_address() {
        let policy = BrokerPolicy::new(
            NetMode::Strict(vec![crate::config::NetRule {
                domain: "example.com".into(),
                port: 443,
            }]),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let pinned = policy
            .authorize("example.com", 443, "93.184.216.34:443".parse().unwrap())
            .unwrap();
        assert_eq!(pinned.addr(), "93.184.216.34:443".parse().unwrap());
        assert_eq!(
            LocalBroker::tls_mode(),
            "TLS pass-through only; no certificate interception or MITM"
        );
    }

    #[test]
    fn build_proxy_env_contains_expected_keys() {
        let vars = build_proxy_env(54321);
        let map: std::collections::HashMap<_, _> = vars.into_iter().collect();
        assert_eq!(
            map.get("HTTP_PROXY"),
            Some(&"http://127.0.0.1:54321".to_string())
        );
        assert_eq!(
            map.get("HTTPS_PROXY"),
            Some(&"http://127.0.0.1:54321".to_string())
        );
        assert_eq!(
            map.get("ALL_PROXY"),
            Some(&"http://127.0.0.1:54321".to_string())
        );
        assert_eq!(
            map.get("http_proxy"),
            Some(&"http://127.0.0.1:54321".to_string())
        );
        assert_eq!(
            map.get("https_proxy"),
            Some(&"http://127.0.0.1:54321".to_string())
        );
        assert_eq!(
            map.get("all_proxy"),
            Some(&"http://127.0.0.1:54321".to_string())
        );
        assert_eq!(map.get("NO_PROXY"), Some(&String::new()));
        assert_eq!(map.get("no_proxy"), Some(&String::new()));
    }

    #[test]
    fn local_broker_connect_disallowed_domain_forbidden() {
        let policy = BrokerPolicy::new(
            NetMode::Allowlist(vec!["allowed.com".into()]),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let broker = LocalBroker::bind(policy).unwrap();
        let port = broker.local_addr().unwrap().port();
        let handle = broker.start().unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .write_all(b"CONNECT forbidden.com:443 HTTP/1.1\r\nHost: forbidden.com:443\r\n\r\n")
            .unwrap();

        let mut response = String::new();
        let _ = client.read_to_string(&mut response);
        assert!(response.contains("403 Forbidden"), "response: {response}");

        handle.stop();
    }

    #[test]
    fn extract_client_hello_sni_parses_valid_sni() {
        let host = b"example.com";
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        let list_len = (host.len() + 3) as u16;
        let ext_len = list_len + 2;
        ext.extend_from_slice(&ext_len.to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.push(0x00);
        ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
        ext.extend_from_slice(host);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let body_len = 2 + 32 + 1 + 2 + 1 + 2 + ext.len();
        handshake.extend_from_slice(&(body_len as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&0x0303u16.to_be_bytes());
        handshake.extend_from_slice(&[0u8; 32]);
        handshake.push(0x00);
        handshake.extend_from_slice(&0x0000u16.to_be_bytes());
        handshake.push(0x00);
        handshake.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&ext);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        assert_eq!(
            extract_client_hello_sni(&record),
            Some("example.com".to_string())
        );
        assert_eq!(extract_client_hello_sni(&[0x15, 0x03, 0x01]), None);
        assert_eq!(extract_client_hello_sni(&[]), None);
    }

    #[test]
    fn host_matches_handles_ports_and_wildcards() {
        assert!(host_matches("crates.io", "crates.io:443"));
        assert!(host_matches("crates.io:443", "crates.io"));
        assert!(host_matches("crates.io:443", "crates.io:443"));
        assert!(host_matches("index.crates.io", "crates.io"));
        assert!(host_matches("index.crates.io:443", "crates.io:443"));
        assert!(host_matches("api.github.com", "*.github.com:443"));
        assert!(host_matches("api.github.com:443", "*.github.com"));
        assert!(!host_matches("github.com", "*.github.com:443"));
        assert!(!host_matches("notgithub.com", "*.github.com:443"));
    }
}
