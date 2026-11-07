//! Network Guard: blocks inbound and outbound IPv4 connections to known-bad
//! networks using the Windows Filtering Platform management API.
//!
//! No driver is involved. Filters are added in a *dynamic* WFP session that
//! belongs to the service process, so Windows removes them automatically if
//! the service stops or crashes: a bug here can never leave the PC offline.
//!
//! Lists:
//! * Spamhaus DROP (`drop_v4.json`): networks controlled by spammers and
//!   cyber-criminals (hijacked / bulletproof ranges). Free; fetched at most daily.
//! * `<data dir>\network\blocklist.txt`: your own entries, one IPv4 or CIDR per line.
//!
//! IP filtering cannot see domain names, so this does not block "suspicious TLDs";
//! that needs a DNS-level filter.

use anyhow::Result;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub const SPAMHAUS_DROP_V4: &str = "https://www.spamhaus.org/drop/drop_v4.json";
const MAX_RANGES: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    pub addr: u32,
    pub prefix: u8,
}

impl Range {
    pub fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    #[cfg(test)]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask()) == self.addr
    }

    /// Never block these, whatever a list says: it would break the PC itself.
    fn is_protected(&self) -> bool {
        let first = Ipv4Addr::from(self.addr);
        self.prefix < 8 || first.is_loopback() || first.is_private() || first.is_link_local() || first.is_unspecified()
    }
}

impl std::fmt::Display for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.addr), self.prefix)
    }
}

fn parse_token(tok: &str) -> Option<Range> {
    let tok = tok.trim().trim_matches(|c| c == '"' || c == ',' || c == ';');
    let (ip, prefix) = match tok.split_once('/') {
        Some((ip, p)) => (ip, p.parse::<u8>().ok().filter(|p| *p <= 32)?),
        None => (tok, 32),
    };
    let ip: Ipv4Addr = ip.parse().ok()?;
    let mut r = Range {
        addr: u32::from(ip),
        prefix,
    };
    r.addr &= r.mask(); // normalise host bits
    (!r.is_protected()).then_some(r)
}

/// Accepts plain lists (`1.2.3.0/24 ; SBL123`, comments with `#`/`;`) and
/// Spamhaus JSON lines (`{"cidr":"1.2.3.0/24","sblid":"SBL1",...}`).
pub fn parse_list(text: &str) -> Vec<Range> {
    let mut out: Vec<Range> = text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                return None;
            }
            if let Some(rest) = line.split("\"cidr\"").nth(1) {
                let value = rest.split('"').nth(1)?;
                return parse_token(value);
            }
            parse_token(line.split(|c: char| c.is_whitespace() || c == ';' || c == '#').next()?)
        })
        .take(MAX_RANGES)
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn list_dir(data: &Path) -> PathBuf {
    data.join("network")
}

/// All ranges currently configured (downloaded + personal).
pub fn load_ranges(data: &Path) -> Vec<Range> {
    let dir = list_dir(data);
    let mut all = Vec::new();
    for name in ["spamhaus-drop-v4.txt", "blocklist.txt"] {
        if let Ok(text) = std::fs::read_to_string(dir.join(name)) {
            all.extend(parse_list(&text));
        }
    }
    all.sort();
    all.dedup();
    all
}

/// Download Spamhaus DROP and store it normalised. Returns the range count.
pub fn update_drop(data: &Path) -> Result<usize> {
    let body = super::update::fetch(SPAMHAUS_DROP_V4)?;
    let ranges = parse_list(&String::from_utf8_lossy(&body));
    anyhow::ensure!(
        ranges.len() >= 50,
        "Spamhaus DROP returned only {} ranges",
        ranges.len()
    );
    let dir = list_dir(data);
    std::fs::create_dir_all(&dir)?;
    let text: String = ranges.iter().map(|r| format!("{r}\n")).collect();
    let tmp = dir.join("spamhaus-drop-v4.txt.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, dir.join("spamhaus-drop-v4.txt"))?;
    Ok(ranges.len())
}

pub use imp::Firewall;

#[cfg(windows)]
mod imp {
    use super::Range;
    use anyhow::{bail, Result};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    // Our own sub-layer, so our filters are evaluated independently of others'.
    const SUBLAYER: GUID = GUID::from_u128(0x5e471e4c_0a7d_4c1b_9b39_7d2a6f3c1a51);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// An open dynamic WFP session holding our block filters.
    pub struct Firewall {
        engine: HANDLE,
        pub ranges: usize,
    }

    unsafe impl Send for Firewall {}
    unsafe impl Sync for Firewall {}

    impl Drop for Firewall {
        fn drop(&mut self) {
            // Closing a dynamic session deletes all of its filters.
            unsafe { FwpmEngineClose0(self.engine) };
        }
    }

    fn check(code: u32, what: &str) -> Result<()> {
        if code != 0 {
            bail!("{what} failed (WFP error 0x{code:08X})");
        }
        Ok(())
    }

    impl Firewall {
        pub fn install(ranges: &[Range]) -> Result<Self> {
            let name = wide("Sentinel-Lite Network Guard");
            let desc = wide("Blocks connections to known-malicious networks");
            unsafe {
                let mut session: FWPM_SESSION0 = std::mem::zeroed();
                session.flags = FWPM_SESSION_FLAG_DYNAMIC;
                session.displayData.name = name.as_ptr() as *mut u16;
                let mut engine: HANDLE = std::ptr::null_mut();
                const RPC_C_AUTHN_WINNT: u32 = 10;
                check(
                    FwpmEngineOpen0(
                        std::ptr::null(),
                        RPC_C_AUTHN_WINNT,
                        std::ptr::null(),
                        &session,
                        &mut engine,
                    ),
                    "FwpmEngineOpen0",
                )?;
                // Owns the session from here on: any early return closes it exactly once.
                // (Never build the result with `..fw`: that copies the handle and then
                // drops `fw`, closing the session under the returned value.)
                let mut fw = Firewall { engine, ranges: 0 };
                check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;
                let result = (|| -> Result<usize> {
                    let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
                    sublayer.subLayerKey = SUBLAYER;
                    sublayer.displayData.name = name.as_ptr() as *mut u16;
                    sublayer.displayData.description = desc.as_ptr() as *mut u16;
                    sublayer.weight = 0x100;
                    check(
                        FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut()),
                        "FwpmSubLayerAdd0",
                    )?;

                    let mut added = 0;
                    for r in ranges {
                        let mut addr_mask = FWP_V4_ADDR_AND_MASK {
                            addr: r.addr,
                            mask: r.mask(),
                        };
                        let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                        cond.matchType = FWP_MATCH_EQUAL;
                        cond.conditionValue.r#type = FWP_V4_ADDR_MASK;
                        cond.conditionValue.Anonymous.v4AddrMask = &mut addr_mask;
                        for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4] {
                            let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                            filter.displayData.name = name.as_ptr() as *mut u16;
                            filter.layerKey = layer;
                            filter.subLayerKey = SUBLAYER;
                            filter.weight.r#type = FWP_EMPTY; // let WFP assign
                            filter.numFilterConditions = 1;
                            filter.filterCondition = &mut cond;
                            filter.action.r#type = FWP_ACTION_BLOCK;
                            check(
                                FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), std::ptr::null_mut()),
                                "FwpmFilterAdd0",
                            )?;
                        }
                        added += 1;
                    }
                    Ok(added)
                })();
                match result {
                    Ok(n) => {
                        check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0")?;
                        fw.ranges = n;
                        Ok(fw)
                    }
                    Err(e) => {
                        FwpmTransactionAbort0(engine);
                        Err(e)
                    }
                }
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Range;
    use anyhow::Result;

    /// Dev hosts: lists are parsed and counted but nothing is enforced.
    pub struct Firewall {
        pub ranges: usize,
    }

    impl Firewall {
        pub fn install(ranges: &[Range]) -> Result<Self> {
            Ok(Self { ranges: ranges.len() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spamhaus_json_and_plain_lists() {
        let json = r#"{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2.56.192.0/22","sblid":"SBL459831","rir":"ripe"}
{"type":"metadata","timestamp":1730937600,"size":2}"#;
        let r = parse_list(json);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].to_string(), "1.10.16.0/20");

        let plain =
            "; Spamhaus DROP\n5.134.128.0/19 ; SBL270738\n# comment\n203.0.113.7\n198.51.100.77/24\nnot an ip\n";
        let r = parse_list(plain);
        let s: Vec<String> = r.iter().map(|r| r.to_string()).collect();
        assert_eq!(
            s,
            vec!["5.134.128.0/19", "198.51.100.0/24", "203.0.113.7/32"],
            "host bits normalised"
        );
    }

    #[test]
    fn never_blocks_local_or_overly_broad_ranges() {
        let r = parse_list("10.0.0.0/8\n192.168.1.0/24\n127.0.0.1\n0.0.0.0/0\n1.0.0.0/4\n169.254.0.0/16\n8.8.8.8\n");
        let s: Vec<String> = r.iter().map(|r| r.to_string()).collect();
        assert_eq!(s, vec!["8.8.8.8/32"]);
    }

    #[test]
    fn contains_and_personal_list_loading() {
        let r = parse_list("198.51.100.0/24")[0];
        assert!(r.contains("198.51.100.200".parse().unwrap()));
        assert!(!r.contains("198.51.101.1".parse().unwrap()));
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(list_dir(dir.path())).unwrap();
        std::fs::write(list_dir(dir.path()).join("blocklist.txt"), "203.0.113.0/24\n").unwrap();
        assert_eq!(load_ranges(dir.path()).len(), 1);
    }
}
