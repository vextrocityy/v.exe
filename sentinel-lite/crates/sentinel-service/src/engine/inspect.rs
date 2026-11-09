//! On-demand file check (the dashboard's File Check page).
//!
//! Produces a detailed, read-only report for each file: hash-list match,
//! every YARA rule that matches (with scores), malicious archive members,
//! Authenticode status, where it was downloaded from (Mark of the Web) and
//! name tricks. Nothing is moved, changed or uploaded.

use super::{archive, hasher, heuristics, yara, Engine};
use sentinel_protocol::{Detection, FileReport, Verdict};
use std::path::{Path, PathBuf};

/// Upper bound on files per request (dropping a whole drive must not hang the UI).
pub const MAX_FILES: usize = 500;

/// Expand folders (recursively, skipping links) and check every file.
pub fn inspect_paths(engine: &Engine, paths: &[String]) -> (Vec<FileReport>, bool) {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut truncated = false;
    let mut stack: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    stack.reverse();
    while let Some(p) = stack.pop() {
        if files.len() >= MAX_FILES {
            truncated = true;
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            files.push(p); // reported as unreadable
            continue;
        };
        if meta.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                let mut children: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                children.sort();
                children.reverse();
                stack.extend(children);
            }
        } else if meta.is_file() {
            files.push(p);
        }
    }
    (files.iter().map(|f| inspect_file(engine, f)).collect(), truncated)
}

fn error_report(path: &Path, size: u64, why: impl Into<String>) -> FileReport {
    FileReport {
        path: path.display().to_string(),
        size,
        sha256: None,
        verdict: Verdict::Error,
        summary: why.into(),
        detections: Vec::new(),
        signed: None,
        downloaded_from: None,
        indicators: Vec::new(),
    }
}

fn is_pe(path: &Path) -> bool {
    let mut magic = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
        .is_ok()
        && &magic == b"MZ"
}

/// Parse a `Zone.Identifier` stream: returns the source URL (or a zone label)
/// when Windows marked the file as coming from the internet (zone 3) or an
/// untrusted site (zone 4).
pub fn parse_zone_identifier(text: &str) -> Option<String> {
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_string()))
            .filter(|v| !v.is_empty())
    };
    let zone: u32 = field("ZoneId=")?.parse().ok()?;
    if zone < 3 {
        return None;
    }
    field("HostUrl=").or_else(|| field("ReferrerUrl=")).or_else(|| {
        Some(if zone == 4 {
            "an untrusted site".into()
        } else {
            "the internet".into()
        })
    })
}

fn mark_of_the_web(path: &Path) -> Option<String> {
    if !cfg!(windows) {
        return None;
    }
    // NTFS alternate data stream written by browsers and mail clients.
    let ads = format!("{}:Zone.Identifier", path.display());
    parse_zone_identifier(&std::fs::read_to_string(ads).ok()?)
}

/// Name tricks used to make an executable look like a document.
pub fn name_indicators(name: &str) -> Vec<String> {
    const EXEC: &[&str] = &[
        "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "lnk", "msi", "cpl",
    ];
    const DOCS: &[&str] = &[
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip",
        "rar",
    ];
    let mut out = Vec::new();
    if name.contains('\u{202E}') {
        out.push(
            "File name contains a hidden right-to-left character (makes \"exe\" look like another extension)".into(),
        );
    }
    let lower = name.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() >= 3 {
        let (last, prev) = (parts[parts.len() - 1], parts[parts.len() - 2].trim_end());
        if EXEC.contains(&last) && DOCS.contains(&prev) {
            out.push(format!(
                "Double extension: looks like a .{prev} but is a .{last} program"
            ));
        }
    }
    if lower.contains("     .") {
        out.push("Long run of spaces before the extension (hides the real extension)".into());
    }
    out
}

pub fn inspect_file(engine: &Engine, path: &Path) -> FileReport {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return error_report(path, 0, format!("Cannot read this file: {e}")),
    };
    let size = meta.len();
    let settings = engine.settings();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut indicators = name_indicators(&name);
    let pe = is_pe(path);
    if pe {
        if let Some(folder) = heuristics::risky_location(path) {
            indicators.push(format!(
                "Program stored in {folder}, where downloaded malware usually lands"
            ));
        }
        let mut buf = vec![0u8; 1024 * 1024];
        let n = std::fs::File::open(path)
            .and_then(|mut f| std::io::Read::read(&mut f, &mut buf))
            .unwrap_or(0);
        if n > 4096 && heuristics::shannon_entropy(&buf[..n]) > 7.2 {
            indicators.push(
                "Program looks packed or encrypted (very high entropy); common for malware, also some installers"
                    .into(),
            );
        }
    }
    let signed = if pe && cfg!(windows) {
        Some(crate::platform::has_valid_signature(path))
    } else {
        None
    };
    let downloaded_from = mark_of_the_web(path);

    let max = settings.max_file_size_mb.saturating_mul(1024 * 1024);
    let sha256 = match hasher::sha256_file(path, max) {
        Ok((h, _)) => Some(h),
        Err(hasher::SkipReason::TooLarge) => None,
        Err(reason) => {
            return error_report(
                path,
                size,
                format!("Cannot read this file ({reason:?}). It may be locked by another program."),
            )
        }
    };

    let mut detections = Vec::new();
    if let Some(sha) = &sha256 {
        if let Ok(Some(hit)) = engine.db.lookup_hash(sha) {
            let source = if hit.is_community() {
                "Known malware hash (community feed)".to_string()
            } else {
                format!("Known malware hash ({})", hit.source)
            };
            detections.push(Detection {
                name: hit.name,
                source,
                score: None,
                description: None,
            });
        }
    }
    if let Some(rules) = engine.yara.rules() {
        if size <= settings.yara_max_file_mb.saturating_mul(1024 * 1024) {
            if let Ok(mut matches) = yara::scan_file(&rules, path) {
                matches.sort_by_key(|m| std::cmp::Reverse(m.score));
                detections.extend(matches.into_iter().map(|m| Detection {
                    name: format!("YARA.{}", m.rule),
                    source: format!("YARA rule ({})", m.namespace),
                    score: Some(m.score),
                    description: m.description,
                }));
            }
        }
    }
    if archive::kind_of_file(path).is_some() {
        if let Some(sha) = &sha256 {
            if let Some(hit) = engine.archive_check(path, sha, size) {
                detections.push(Detection {
                    name: hit.name,
                    source: "Inside the archive".into(),
                    score: hit.score,
                    description: hit.description,
                });
            }
        }
    }

    // Verdict: exact hashes and confident YARA rules are malicious; weaker
    // signals make a file suspicious.
    let threshold = settings.yara_min_remediate_score;
    let strong = detections.iter().any(|d| d.score.is_none_or(|s| s >= threshold));
    let (verdict, summary) = if strong {
        let top = &detections
            .iter()
            .find(|d| d.score.is_none_or(|s| s >= threshold))
            .unwrap()
            .name;
        (Verdict::Malicious, format!("Malicious: matches {top}. Quarantine it."))
    } else if let Some(d) = detections.first() {
        (
            Verdict::Suspicious,
            format!(
                "Suspicious: matches {} with low confidence ({}). Review before opening.",
                d.name,
                d.score.unwrap_or(0)
            ),
        )
    } else if !indicators.is_empty() && signed != Some(true) {
        (
            Verdict::Suspicious,
            format!("Suspicious: {}.", indicators[0].to_lowercase()),
        )
    } else if sha256.is_none() {
        (
            Verdict::NoThreats,
            "Too large to hash; YARA and name checks found nothing.".into(),
        )
    } else if signed == Some(true) {
        (
            Verdict::NoThreats,
            "No threats found. The program has a valid digital signature.".into(),
        )
    } else {
        (
            Verdict::NoThreats,
            "No threats found by signatures, YARA rules or archive scanning.".into(),
        )
    };

    FileReport {
        path: path.display().to_string(),
        size,
        sha256,
        verdict,
        summary,
        detections,
        signed,
        downloaded_from,
        indicators,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_identifier_parsing() {
        let t = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/page\r\nHostUrl=https://cdn.example.com/setup.exe\r\n";
        assert_eq!(
            parse_zone_identifier(t).as_deref(),
            Some("https://cdn.example.com/setup.exe")
        );
        assert_eq!(
            parse_zone_identifier("[ZoneTransfer]\nZoneId=3\n").as_deref(),
            Some("the internet")
        );
        assert_eq!(
            parse_zone_identifier("[ZoneTransfer]\nZoneId=1\nHostUrl=x\n"),
            None,
            "intranet is not flagged"
        );
    }

    #[test]
    fn name_tricks() {
        assert_eq!(name_indicators("invoice.pdf.exe").len(), 1);
        assert_eq!(name_indicators("photo.JPG.scr").len(), 1);
        assert!(name_indicators("report\u{202E}fdp.exe")[0].contains("right-to-left"));
        assert!(
            name_indicators("setup-1.2.3.exe").is_empty(),
            "version numbers are not a double extension"
        );
        assert!(name_indicators("notes.txt").is_empty());
    }
}
