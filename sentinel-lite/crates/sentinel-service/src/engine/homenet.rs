//! Home network integration: a Pi-hole (v6 API) on the local network.
//!
//! * **DNS tamper check.** A domain Pi-hole blocks is resolved through this
//!   PC's own resolver. A blocked answer (0.0.0.0 / ::, or "no such host" while
//!   a normal domain resolves) proves DNS goes through Pi-hole, whatever the
//!   route (LAN, Tailscale). A real address means something bypasses it, which
//!   is what malware does when it rewrites DNS settings.
//! * **Suggestions.** Domains this PC looked up around a detection, read from
//!   Pi-hole's query log, so the user can block where malware phoned home.
//! * **Network-wide blocking.** Pi-hole's exact deny list, so every device in
//!   the house stops resolving a domain, not just this PC.
//!
//! Nothing here blocks automatically: the user picks from the suggestions.

use anyhow::{anyhow, bail, Result};
use sentinel_protocol::DomainSuggestion;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Lookups from this PC inside [around - BEFORE, around + AFTER] are offered.
pub const WINDOW_BEFORE_SECS: i64 = 15 * 60;
pub const WINDOW_AFTER_SECS: i64 = 5 * 60;
/// Most domains accepted by one block request.
pub const MAX_BLOCK: usize = 50;
const MAX_SUGGESTIONS: usize = 100;
/// Resolves everywhere; tells "offline" apart from "test domain blocked as NXDOMAIN".
const CONTROL_DOMAIN: &str = "example.com";
/// Tailscale's DNS resolver: the route this PC uses to reach Pi-hole over Tailscale.
const TAILSCALE_RESOLVER: &str = "100.100.100.100:53";

/// Big services whose domains are offered last and whose root can never be blocked:
/// blocking `microsoft.com` would take Windows Update down for the whole house.
const COMMON: &[&str] = &[
    "akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net", "amazon.com", "amazonaws.com",
    "anthropic.com", "apple.com", "azure.com", "azureedge.net", "bing.com", "claude.ai", "cloudflare.com",
    "cloudflare-dns.com", "cloudfront.net", "digicert.com", "discord.com", "discord.gg", "globalsign.com",
    "github.com", "githubusercontent.com", "google.com", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "icloud.com", "lencr.org", "letsencrypt.org", "live.com", "microsoft.com",
    "microsoftonline.com", "msftconnecttest.com", "msftncsi.com", "msn.com", "nvidia.com", "office.com",
    "office.net", "sectigo.com", "skype.com", "spotify.com", "steamcontent.com", "steampowered.com",
    "tailscale.com", "trafficmanager.net", "windows.com", "windows.net", "windowsupdate.com",
    "youtube.com", "ytimg.com",
];

const LOCAL_SUFFIXES: &[&str] = &[".lan", ".local", ".home", ".home.arpa", ".internal", ".arpa", ".ts.net"];

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Names and addresses
// ---------------------------------------------------------------------------

/// A syntactically valid DNS name with at least two labels.
pub fn valid_domain(d: &str) -> bool {
    if d.len() < 3 || d.len() > 253 || !d.contains('.') {
        return false;
    }
    let labels: Vec<&str> = d.split('.').collect();
    let ok_label = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    };
    labels.iter().all(ok_label) && !labels.last().unwrap().chars().all(|c| c.is_ascii_digit())
}

/// Names that only mean something inside the home network (or reverse lookups).
pub fn is_local(d: &str) -> bool {
    d == "pi.hole" || !d.contains('.') || LOCAL_SUFFIXES.iter().any(|s| d.ends_with(s))
}

/// The big service `d` belongs to, if any.
pub fn common_parent(d: &str) -> Option<&'static str> {
    COMMON
        .iter()
        .copied()
        .find(|c| d == *c || d.strip_suffix(c).is_some_and(|rest| rest.ends_with('.')))
}

/// Clean up a domain the user picked and refuse ones that would break the network.
pub fn blockable(raw: &str) -> Result<String, String> {
    let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.parse::<IpAddr>().is_ok() {
        return Err(format!("{d} is an IP address, not a domain"));
    }
    if !valid_domain(&d) {
        return Err(format!("{raw:?} is not a valid domain"));
    }
    if is_local(&d) {
        return Err(format!("{d} is a local name"));
    }
    if COMMON.contains(&d.as_str()) {
        return Err(format!("blocking {d} would break it for everyone on the network"));
    }
    Ok(d)
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..128).contains(&o[1]) // 100.64.0.0/10: Tailscale addresses
}

/// Only addresses inside the home network (or Tailscale) may receive the Pi-hole password.
fn allowed_host(h: &str) -> bool {
    if let Ok(ip) = h.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || is_cgnat(v4),
            IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
    }
    let valid = !h.is_empty()
        && h.len() <= 253
        && h.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
    valid && is_local(h)
}

/// `host[:port]` from the part of a URL after `scheme://`; IPv6 in brackets.
fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), Some(p.parse().ok()?))),
        None => Some((authority.to_string(), None)),
    }
}

/// `http(s)://host[:port]` for a Pi-hole inside the home network, or `None`.
/// Accepts what people paste from the browser (`…/admin/`).
pub fn normalize_url(raw: &str) -> Option<String> {
    let t = raw.trim().trim_end_matches('/');
    let t = t.strip_suffix("/admin").unwrap_or(t).trim_end_matches('/');
    let lower = t.to_ascii_lowercase();
    let (scheme, authority) = lower.split_once("://")?;
    if !matches!(scheme, "http" | "https") || authority.is_empty() || authority.contains(['/', '?', '#', '@', ' ', '\\']) {
        return None;
    }
    let (host, _) = split_host_port(authority)?;
    allowed_host(&host).then(|| format!("{scheme}://{authority}"))
}

/// The addresses this PC uses to talk to Pi-hole: its LAN address towards the
/// Pi-hole host and, with Tailscale running, its Tailscale address. Pi-hole
/// logs queries under these. No packets are sent: `connect` on UDP only picks a route.
pub fn local_ips(pihole_url: &str) -> Vec<String> {
    let mut targets: Vec<SocketAddr> = Vec::new();
    if let Some((_, authority)) = pihole_url.split_once("://") {
        if let Some((host, _)) = split_host_port(authority) {
            if let Ok(mut addrs) = (host.as_str(), 53).to_socket_addrs() {
                targets.extend(addrs.next());
            }
        }
    }
    targets.extend(TAILSCALE_RESOLVER.parse::<SocketAddr>().ok());
    let mut out: Vec<String> = Vec::new();
    for t in targets {
        let bind = if t.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let Ok(sock) = UdpSocket::bind(bind) else { continue };
        if sock.connect(t).is_err() {
            continue;
        }
        if let Ok(a) = sock.local_addr() {
            let ip = a.ip();
            if !ip.is_unspecified() && !ip.is_loopback() && !out.contains(&ip.to_string()) {
                out.push(ip.to_string());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// DNS tamper check
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum DnsVerdict {
    /// DNS from this PC is filtered by Pi-hole.
    Filtered(String),
    /// The test domain resolved to a real address: Pi-hole is being bypassed.
    Unfiltered(String),
    /// Could not tell (lookups failing).
    Unknown(String),
}

fn is_sinkhole(ip: &IpAddr) -> bool {
    ip.is_unspecified() || ip.is_loopback()
}

/// Pure decision, unit-tested: `test` is the lookup of the blocked test
/// domain, `control_resolves` whether a normal domain resolved.
pub fn classify(domain: &str, test: std::io::Result<Vec<IpAddr>>, control_resolves: bool) -> DnsVerdict {
    match test {
        Ok(addrs) if addrs.iter().all(is_sinkhole) => {
            DnsVerdict::Filtered(format!("{domain} is blocked for this PC, so its DNS goes through Pi-hole"))
        }
        Ok(addrs) => {
            let real = addrs.iter().find(|a| !is_sinkhole(a)).expect("not all sinkholes");
            DnsVerdict::Unfiltered(format!(
                "{domain} resolved to {real}: this PC's DNS is not going through Pi-hole"
            ))
        }
        Err(_) if control_resolves => {
            DnsVerdict::Filtered(format!("{domain} does not resolve while other sites do: blocked by Pi-hole"))
        }
        Err(e) => DnsVerdict::Unknown(format!("DNS lookups are failing ({e}); offline?")),
    }
}

fn resolve(domain: &str) -> std::io::Result<Vec<IpAddr>> {
    Ok((domain, 0).to_socket_addrs()?.map(|a| a.ip()).collect())
}

/// Resolve the test domain through this PC's own resolver (the same path apps use).
pub fn check_dns(test_domain: &str) -> DnsVerdict {
    let test = resolve(test_domain);
    let control = resolve(CONTROL_DOMAIN).map(|v| !v.is_empty()).unwrap_or(false);
    classify(test_domain, test, control)
}

// ---------------------------------------------------------------------------
// Pi-hole v6 API
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    pub total: Option<u64>,
    pub blocked: Option<u64>,
    pub percent: Option<f64>,
    pub gravity: Option<u64>,
}

pub fn parse_summary(v: &Value) -> Summary {
    Summary {
        total: v["queries"]["total"].as_u64(),
        blocked: v["queries"]["blocked"].as_u64(),
        percent: v["queries"]["percent_blocked"].as_f64(),
        gravity: v["gravity"]["domains_being_blocked"].as_u64(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub time: i64,
    pub domain: String,
    pub client: String,
    pub status: String,
}

pub fn parse_queries(v: &Value) -> Vec<Query> {
    v["queries"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|q| {
                    Some(Query {
                        time: q["time"].as_f64()? as i64,
                        domain: q["domain"].as_str()?.trim_end_matches('.').to_ascii_lowercase(),
                        client: q["client"]["ip"].as_str().unwrap_or_default().to_string(),
                        status: q["status"].as_str().unwrap_or_default().to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Statuses Pi-hole uses for queries it blocked.
pub fn is_blocked_status(s: &str) -> bool {
    let s = s.to_ascii_uppercase();
    s.contains("GRAVITY") || s.contains("REGEX") || s.contains("DENYLIST") || s.starts_with("EXTERNAL_BLOCKED") || s == "SPECIAL_DOMAIN"
}

fn api_error(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            let e = &v["error"];
            e["message"].as_str().or(e["key"].as_str()).map(str::to_string)
        })
        .unwrap_or_else(|| body.chars().take(200).collect())
}

/// One Pi-hole, with its login session reused until it expires (Pi-hole only
/// allows a handful of sessions at once).
pub struct Pihole {
    pub base: String,
    password: Option<String>,
    session: Mutex<Option<(String, Instant)>>,
}

impl Pihole {
    pub fn new(base: String, password: Option<String>) -> Self {
        Self { base, password, session: Mutex::new(None) }
    }

    pub fn same_config(&self, base: &str, password: &Option<String>) -> bool {
        self.base == base && &self.password == password
    }

    fn agent() -> ureq::Agent {
        ureq::AgentBuilder::new()
            .tls_config(super::update::tls_config())
            .timeout_connect(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("Vigil/", env!("CARGO_PKG_VERSION")))
            .try_proxy_from_env(false) // the Pi-hole is on the home network
            .build()
    }

    /// Session id for API calls; `None` when Pi-hole has no password set.
    fn sid(&self, fresh: bool) -> Result<Option<String>> {
        let Some(pw) = &self.password else { return Ok(None) };
        let mut cached = lock(&self.session);
        if !fresh {
            if let Some((sid, until)) = cached.as_ref() {
                if Instant::now() < *until {
                    return Ok(Some(sid.clone()));
                }
            }
        }
        let resp = Self::agent()
            .post(&format!("{}/api/auth", self.base))
            .set("Content-Type", "application/json")
            .send_string(&json!({ "password": pw }).to_string());
        let v: Value = match resp {
            Ok(r) => serde_json::from_str(&r.into_string()?)?,
            Err(ureq::Error::Status(401, _)) => bail!(
                "Pi-hole rejected the password. Use an app password from Pi-hole's Settings > Web interface / API"
            ),
            Err(ureq::Error::Status(429, _)) => bail!("Pi-hole has too many open sessions; try again in a few minutes"),
            Err(e) => return Err(anyhow!(e).context(format!("could not reach Pi-hole at {}", self.base))),
        };
        let session = &v["session"];
        if session["valid"].as_bool() != Some(true) {
            bail!("Pi-hole rejected the password");
        }
        let Some(sid) = session["sid"].as_str().filter(|s| !s.is_empty()).map(str::to_string) else {
            *cached = None;
            return Ok(None); // valid without a session: Pi-hole has no password
        };
        let validity = session["validity"].as_u64().unwrap_or(300).max(90);
        *cached = Some((sid.clone(), Instant::now() + Duration::from_secs(validity - 60)));
        Ok(Some(sid))
    }

    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        for attempt in 0..2 {
            let sid = self.sid(attempt > 0)?;
            let mut req = Self::agent().request(method, &format!("{}{path}", self.base));
            if let Some(s) = &sid {
                req = req.set("X-FTL-SID", s);
            }
            let res = match body {
                Some(b) => req.set("Content-Type", "application/json").send_string(&b.to_string()),
                None => req.call(),
            };
            match res {
                Ok(r) => {
                    let text = r.into_string()?;
                    return Ok(if text.trim().is_empty() { Value::Null } else { serde_json::from_str(&text)? });
                }
                // Session expired early (Pi-hole restarted): log in again once.
                Err(ureq::Error::Status(401, _)) if attempt == 0 && sid.is_some() => continue,
                Err(ureq::Error::Status(401, _)) => {
                    bail!("Pi-hole needs a password: add its app password in Vigil's settings")
                }
                Err(ureq::Error::Status(403, r)) if method != "GET" => {
                    let msg = api_error(&r.into_string().unwrap_or_default());
                    bail!(
                        "Pi-hole refused the change ({msg}). App passwords can only change Pi-hole when \
                         webserver.api.app_sudo is on: Pi-hole > Settings > All settings > Webserver and API"
                    )
                }
                Err(ureq::Error::Status(code, r)) => {
                    let msg = api_error(&r.into_string().unwrap_or_default());
                    bail!("Pi-hole answered HTTP {code}: {msg}")
                }
                Err(e) => return Err(anyhow!(e).context(format!("could not reach Pi-hole at {}", self.base))),
            }
        }
        unreachable!("the loop returns or bails on its second pass")
    }

    pub fn summary(&self) -> Result<Summary> {
        Ok(parse_summary(&self.request("GET", "/api/stats/summary", None)?))
    }

    /// Queries from `client` between `from` and `until` (unix seconds).
    pub fn queries(&self, from: i64, until: i64, client: &str) -> Result<Vec<Query>> {
        let path = format!("/api/queries?from={from}&until={until}&length=5000&client_ip={client}");
        Ok(parse_queries(&self.request("GET", &path, None)?))
    }

    /// The network's most looked-up domains (treated as "usually safe").
    pub fn top_domains(&self, count: u32) -> Result<HashSet<String>> {
        let v = self.request("GET", &format!("/api/stats/top_domains?count={count}"), None)?;
        Ok(v["domains"]
            .as_array()
            .map(|a| a.iter().filter_map(|d| d["domain"].as_str()).map(|d| d.to_ascii_lowercase()).collect())
            .unwrap_or_default())
    }

    /// Add `domain` to Pi-hole's exact deny list. Already listed counts as success.
    pub fn deny(&self, domain: &str, comment: &str) -> Result<()> {
        let body = json!({ "domain": domain, "comment": comment, "groups": [0], "enabled": true });
        let v = self.request("POST", "/api/domains/deny/exact", Some(&body))?;
        if let Some(errors) = v["processed"]["errors"].as_array() {
            for e in errors {
                let msg = e["error"].as_str().unwrap_or("unknown error");
                if !msg.to_ascii_lowercase().contains("unique") {
                    bail!("{msg}");
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Suggestions
// ---------------------------------------------------------------------------

/// Group this PC's lookups by domain, most interesting first: unknown domains,
/// then ones Pi-hole already blocks, then big services and household favourites.
pub fn build_suggestions(queries: &[Query], frequent: &HashSet<String>) -> Vec<DomainSuggestion> {
    let mut by_domain: HashMap<String, DomainSuggestion> = HashMap::new();
    for q in queries {
        if !valid_domain(&q.domain) || is_local(&q.domain) {
            continue;
        }
        let e = by_domain.entry(q.domain.clone()).or_insert_with(|| DomainSuggestion {
            domain: q.domain.clone(),
            queries: 0,
            first_seen: q.time,
            last_seen: q.time,
            already_blocked: false,
            note: None,
        });
        e.queries += 1;
        e.first_seen = e.first_seen.min(q.time);
        e.last_seen = e.last_seen.max(q.time);
        e.already_blocked |= is_blocked_status(&q.status);
    }
    let mut out: Vec<DomainSuggestion> = by_domain
        .into_values()
        .map(|mut s| {
            s.note = if let Some(parent) = common_parent(&s.domain) {
                Some(format!("Part of {parent}, a widely used service; usually safe"))
            } else if frequent.contains(&s.domain) {
                Some("Looked up often on your network; usually safe".into())
            } else {
                None
            };
            s
        })
        .collect();
    out.sort_by(|a, b| {
        (a.note.is_some(), a.already_blocked, a.first_seen, &a.domain).cmp(&(
            b.note.is_some(),
            b.already_blocked,
            b.first_seen,
            &b.domain,
        ))
    });
    out.truncate(MAX_SUGGESTIONS);
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    /// A fake Pi-hole on 127.0.0.1: `handler(request line, body)` → (status, JSON). Serves until the test ends.
    pub(crate) fn fake_pihole(handler: impl Fn(&str, &str) -> (u16, String) + Send + 'static) -> String {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() {
                    continue;
                }
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; len];
                let _ = reader.read_exact(&mut body);
                let (code, resp) = handler(first.trim_end(), &String::from_utf8_lossy(&body));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                    resp.len()
                );
            }
        });
        base
    }

    #[test]
    fn urls_must_stay_inside_the_home_network() {
        assert_eq!(normalize_url(" http://192.168.88.6/admin/ ").as_deref(), Some("http://192.168.88.6"));
        assert_eq!(normalize_url("https://100.111.234.45:8443").as_deref(), Some("https://100.111.234.45:8443"));
        assert_eq!(normalize_url("http://pi.hole").as_deref(), Some("http://pi.hole"));
        assert_eq!(normalize_url("http://homeserver").as_deref(), Some("http://homeserver"));
        assert_eq!(normalize_url("http://homeserver.lan:8080").as_deref(), Some("http://homeserver.lan:8080"));
        assert_eq!(normalize_url("http://[fd00::1]").as_deref(), Some("http://[fd00::1]"));
        for bad in [
            "http://8.8.8.8",
            "http://evil.example.com",
            "ftp://192.168.1.2",
            "192.168.1.2",
            "http://user@192.168.1.2",
            "http://192.168.1.2/api?x",
            "http://100.200.1.1",
            "http://192.168.1.2:notaport",
        ] {
            assert_eq!(normalize_url(bad), None, "{bad}");
        }
    }

    #[test]
    fn dns_verdicts() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(matches!(classify("ads.test", Ok(vec![ip("0.0.0.0"), ip("::")]), true), DnsVerdict::Filtered(_)));
        assert!(matches!(classify("ads.test", Ok(vec![ip("142.250.1.1")]), true), DnsVerdict::Unfiltered(_)));
        assert!(matches!(
            classify("ads.test", Ok(vec![ip("0.0.0.0"), ip("142.250.1.1")]), true),
            DnsVerdict::Unfiltered(_)
        ));
        let nx = || Err(Error::new(ErrorKind::NotFound, "no such host"));
        assert!(matches!(classify("ads.test", nx(), true), DnsVerdict::Filtered(_)), "NXDOMAIN blocking mode");
        assert!(matches!(classify("ads.test", nx(), false), DnsVerdict::Unknown(_)), "offline is not an alarm");
    }

    #[test]
    fn blocking_refuses_names_that_would_break_the_network() {
        assert_eq!(blockable(" Evil-C2.Example.COM. ").as_deref(), Ok("evil-c2.example.com"));
        assert_eq!(blockable("bad-bucket.s3.amazonaws.com").as_deref(), Ok("bad-bucket.s3.amazonaws.com"));
        for bad in ["microsoft.com", "google.com", "homeserver.lan", "pi.hole", "1.2.3.4", "com", "-x.com", "a..b"] {
            assert!(blockable(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_pihole_v6_responses() {
        let s = parse_summary(&json!({
            "queries": {"total": 1200, "blocked": 300, "percent_blocked": 25.0},
            "gravity": {"domains_being_blocked": 412345}
        }));
        assert_eq!(s, Summary { total: Some(1200), blocked: Some(300), percent: Some(25.0), gravity: Some(412345) });
        let q = parse_queries(&json!({"queries": [
            {"time": 1763460000.5, "domain": "Evil.Example.", "client": {"ip": "192.168.88.2", "name": "pc"}, "status": "FORWARDED"},
            {"time": 1763460001.0, "domain": "ads.example", "client": {"ip": "192.168.88.2"}, "status": "GRAVITY"},
            {"domain": "no-time.example"}
        ]}));
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].domain, "evil.example");
        assert_eq!(q[0].time, 1763460000);
        assert!(is_blocked_status(&q[1].status));
        assert!(!is_blocked_status("CACHE"));
        assert_eq!(api_error(r#"{"error":{"key":"bad_request","message":"Invalid domain"}}"#), "Invalid domain");
    }

    #[test]
    fn suggestions_put_unknown_domains_first() {
        let q = |t: i64, d: &str, st: &str| Query { time: t, domain: d.into(), client: "192.168.88.2".into(), status: st.into() };
        let queries = vec![
            q(100, "update.microsoft.com", "FORWARDED"),
            q(101, "weird-c2.example", "FORWARDED"),
            q(105, "weird-c2.example", "CACHE"),
            q(102, "tracker.example", "GRAVITY"),
            q(103, "netflix.com", "FORWARDED"),
            q(104, "homeserver.lan", "FORWARDED"),
            q(104, "6.88.168.192.in-addr.arpa", "FORWARDED"),
        ];
        let frequent: HashSet<String> = ["netflix.com".to_string()].into();
        let s = build_suggestions(&queries, &frequent);
        let names: Vec<&str> = s.iter().map(|s| s.domain.as_str()).collect();
        assert_eq!(names, vec!["weird-c2.example", "tracker.example", "update.microsoft.com", "netflix.com"]);
        assert_eq!((s[0].queries, s[0].first_seen, s[0].last_seen), (2, 101, 105));
        assert!(s[1].already_blocked);
        assert!(s[2].note.as_deref().unwrap().contains("microsoft.com"));
        assert!(s[3].note.as_deref().unwrap().contains("often"));
    }

    #[test]
    fn host_port_parsing() {
        assert_eq!(split_host_port("192.168.1.2:80"), Some(("192.168.1.2".into(), Some(80))));
        assert_eq!(split_host_port("[fd00::1]:8080"), Some(("fd00::1".into(), Some(8080))));
        assert_eq!(split_host_port("pi.hole"), Some(("pi.hole".into(), None)));
        assert_eq!(split_host_port("[fd00::1]x"), None);
    }

    /// Talks to a fake Pi-hole: login once, reuse the session, re-login after a 401.
    #[test]
    fn api_client_logs_in_and_reuses_the_session() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let logins = Arc::new(AtomicUsize::new(0));
        let l2 = logins.clone();
        std::thread::spawn(move || {
            let mut summary_calls = 0;
            for stream in listener.incoming().take(6) {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let mut len = 0usize;
                let mut sid = None;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    if h == "\r\n" || h.is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    if let Some(v) = lower.strip_prefix("x-ftl-sid:") {
                        sid = Some(v.trim().to_string());
                    }
                }
                let mut body = vec![0; len];
                std::io::Read::read_exact(&mut reader, &mut body).unwrap();
                let (code, resp) = if first.starts_with("POST /api/auth") {
                    assert!(String::from_utf8_lossy(&body).contains("app-pw"));
                    let n = l2.fetch_add(1, Ordering::SeqCst) + 1;
                    (200, format!(r#"{{"session":{{"valid":true,"sid":"sid{n}","validity":1800}}}}"#))
                } else if first.starts_with("GET /api/stats/summary") {
                    summary_calls += 1;
                    if summary_calls == 2 {
                        (401, r#"{"error":{"key":"unauthorized","message":"Unauthorized"}}"#.to_string())
                    } else {
                        assert!(sid.is_some(), "session id sent");
                        (200, r#"{"queries":{"total":10,"blocked":2,"percent_blocked":20.0},"gravity":{"domains_being_blocked":5}}"#.to_string())
                    }
                } else {
                    (404, "{}".to_string())
                };
                let status = if code == 200 { "200 OK" } else if code == 401 { "401 Unauthorized" } else { "404 Not Found" };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                    resp.len()
                );
            }
        });
        let ph = Pihole::new(base, Some("app-pw".into()));
        assert_eq!(ph.summary().unwrap().total, Some(10)); // login 1 + summary
        assert_eq!(ph.summary().unwrap().blocked, Some(2)); // 401 → login 2 → summary
        assert_eq!(ph.summary().unwrap().gravity, Some(5)); // reuses session 2
        assert_eq!(logins.load(Ordering::SeqCst), 2);
    }
}
