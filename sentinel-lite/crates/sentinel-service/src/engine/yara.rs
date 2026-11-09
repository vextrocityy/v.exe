//! YARA rule engine (VirusTotal's pure-Rust YARA-X).
//!
//! Rules let us catch *families and variants* that no hash list has seen yet.
//! Sources, compiled together (one namespace per file):
//!
//! * `<exe dir>/rules/*.yar`             bundled with the installer
//! * `<data dir>/rules/*.yar`            added by an administrator
//! * `<data dir>/rules/feeds/*.yar`      downloaded feeds (YARA Forge "core")
//!
//! A file that fails to compile is skipped and reported; the rest still load.
//! Matches carry the rule's `score` metadata (YARA Forge convention, 0–100);
//! only matches at or above `yara_min_remediate_score` may quarantine, and
//! they pass the same safety gate as community hashes (never Windows system
//! files or validly code-signed binaries). Everything else is an alert.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Score assumed when a rule has no `score` metadata: alert-only by default.
pub const DEFAULT_SCORE: u32 = 70;
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

pub struct RuleSet {
    rules: yara_x::Rules,
    /// Fingerprint of all sources; scan results are cached per version.
    pub version: String,
    pub rule_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub score: u32,
    pub description: Option<String>,
}

#[derive(Default)]
pub struct CompileReport {
    pub loaded_files: usize,
    pub errors: Vec<String>,
}

fn rule_files(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            let ext = p.extension().and_then(|x| x.to_str()).map(|x| x.to_ascii_lowercase());
            if p.is_file() && matches!(ext.as_deref(), Some("yar" | "yara")) {
                files.push(p);
            }
        }
    }
    files.sort();
    files
}

/// Fingerprint of every rule source (file name + content); the compiled cache
/// and verdict cache are only valid for the fingerprint they were built from.
/// Folder locations are deliberately left out, so moving the install folder
/// (as the Sentinel-Lite → Vigil upgrade did) does not force a recompile.
pub fn fingerprint(dirs: &[PathBuf]) -> String {
    let mut parts: Vec<(String, Vec<u8>)> = rule_files(dirs)
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            let digest = std::fs::read(&p).map(|src| Sha256::digest(&src).to_vec()).unwrap_or_default();
            (name, digest)
        })
        .collect();
    parts.sort();
    let mut h = Sha256::new();
    for (name, digest) in parts {
        h.update(name.as_bytes());
        h.update([0]);
        h.update(digest);
    }
    super::hasher::to_hex(&h.finalize())[..16].to_string()
}

/// Where rules come from for a given installation.
pub fn rule_dirs(paths: &crate::engine::AppPaths) -> Vec<PathBuf> {
    let mut dirs = vec![paths.data.join("rules"), feeds_dir(paths)];
    if let Some(dir) = crate::platform::install_dir() {
        dirs.push(dir.join("rules"));
    }
    if let Some(extra) = std::env::var_os("SENTINEL_RULES") {
        dirs.push(PathBuf::from(extra));
    }
    // Dev convenience: `cargo run` from the workspace.
    dirs.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules"));
    dirs.sort();
    dirs.dedup();
    dirs
}

pub fn feeds_dir(paths: &crate::engine::AppPaths) -> PathBuf {
    paths.data.join("rules").join("feeds")
}

pub fn compiled_path(paths: &crate::engine::AppPaths) -> PathBuf {
    paths.data.join("rules").join("compiled.bin")
}

fn namespace_for(path: &Path) -> String {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    stem.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Compile every rule file in `dirs`. Returns `None` if there are no usable rules.
pub fn compile(dirs: &[PathBuf]) -> (Option<RuleSet>, CompileReport) {
    let mut report = CompileReport::default();
    let mut compiler = yara_x::Compiler::new();
    let mut files = Vec::new();

    for path in rule_files(dirs) {
        let src = match std::fs::read(&path) {
            Ok(s) => s,
            Err(e) => {
                report.errors.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        compiler.new_namespace(&namespace_for(&path));
        // On error YARA-X leaves the compiler as it was before this source.
        match compiler.add_source(src.as_slice()) {
            Ok(_) => files.push(path.display().to_string()),
            Err(e) => {
                let first_line = e.to_string().lines().next().unwrap_or_default().to_string();
                report.errors.push(format!("{}: {first_line}", path.display()));
            }
        }
    }
    if files.is_empty() {
        return (None, report);
    }
    let rules = compiler.build();
    let rule_count = rules.iter().count();
    report.loaded_files = files.len();
    (
        Some(RuleSet {
            rules,
            version: fingerprint(dirs),
            rule_count,
        }),
        report,
    )
}

impl RuleSet {
    /// Serialized form: `version\n` + YARA-X compiled rules.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.version.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(&self.rules.serialize().context("serializing rules")?);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let nl = bytes
            .iter()
            .position(|b| *b == b'\n')
            .context("corrupt compiled rules")?;
        let version = String::from_utf8_lossy(&bytes[..nl]).into_owned();
        let rules = yara_x::Rules::deserialize(&bytes[nl + 1..]).context("deserializing rules")?;
        let rule_count = rules.iter().count();
        Ok(Self {
            rules,
            version,
            rule_count,
        })
    }
}

/// Test-compile one candidate file in isolation (used before installing a download).
pub fn validate(src: &[u8]) -> Result<usize> {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(src)
        .map_err(|e| anyhow::anyhow!("{}", e.to_string().lines().next().unwrap_or("compile error")))?;
    Ok(compiler.build().iter().count())
}

/// Is this file worth running YARA on? Executables, scripts, shortcuts and
/// documents, identified by magic bytes or extension. Media, archives of
/// unknown type and plain data are skipped to keep scans cheap.
pub fn is_candidate(path: &Path) -> bool {
    if path.extension().and_then(|x| x.to_str()).is_some_and(is_candidate_ext) {
        return true;
    }
    let mut magic = [0u8; 4];
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    std::io::Read::read(&mut f, &mut magic).unwrap_or(0) >= 4 && is_candidate_magic(&magic)
}

/// Same test for an in-memory archive member.
pub fn is_candidate_member(name: &str, data: &[u8]) -> bool {
    name.rsplit('.')
        .next()
        .is_some_and(|ext| ext != name && is_candidate_ext(ext))
        || data.get(..4).is_some_and(|m| is_candidate_magic(m.try_into().unwrap()))
}

fn is_candidate_ext(ext: &str) -> bool {
    const SCRIPT_EXT: &[&str] = &[
        "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "lnk", "scr", "py", "sh", "doc",
        "docm", "xls", "xlsm", "ppt", "pptm", "rtf", "pdf", "one", "msi", "jar", "dll", "exe", "sys",
    ];
    SCRIPT_EXT.contains(&ext.to_ascii_lowercase().as_str())
}

fn is_candidate_magic(magic: &[u8; 4]) -> bool {
    magic[..2] == *b"MZ"                                     // PE
        || *magic == *b"\x7fELF"                            // ELF
        || matches!(magic, [0xCF | 0xCE, 0xFA, 0xED, 0xFE]) // Mach-O
        || *magic == [0xD0, 0xCF, 0x11, 0xE0]               // OLE (legacy Office, MSI, vbaProject.bin)
        || *magic == *b"%PDF"
        || *magic == *b"{\\rt"
}

pub fn scan_file(set: &RuleSet, path: &Path) -> Result<Vec<YaraMatch>> {
    let mut scanner = yara_x::Scanner::new(&set.rules);
    scanner.set_timeout(SCAN_TIMEOUT);
    let results = scanner
        .scan_file(path)
        .with_context(|| format!("YARA scan of {}", path.display()))?;
    Ok(collect(results))
}

/// Scan an in-memory buffer (archive members).
pub fn scan_bytes(set: &RuleSet, data: &[u8]) -> Result<Vec<YaraMatch>> {
    let mut scanner = yara_x::Scanner::new(&set.rules);
    scanner.set_timeout(SCAN_TIMEOUT);
    let results = scanner.scan(data).context("YARA scan of archive member")?;
    Ok(collect(results))
}

fn collect(results: yara_x::ScanResults<'_, '_>) -> Vec<YaraMatch> {
    results
        .matching_rules()
        .map(|r| {
            let mut score = None;
            let mut description = None;
            for (key, value) in r.metadata() {
                match (key, value) {
                    ("score", yara_x::MetaValue::Integer(v)) => score = Some(v.clamp(0, 100) as u32),
                    ("description", yara_x::MetaValue::String(s)) => description = Some(s.to_string()),
                    _ => {}
                }
            }
            YaraMatch {
                rule: r.identifier().to_string(),
                namespace: r.namespace().to_string(),
                score: score.unwrap_or(DEFAULT_SCORE),
                description,
            }
        })
        .collect()
}

/// The strongest match decides the verdict.
pub fn strongest(matches: &[YaraMatch]) -> Option<&YaraMatch> {
    matches.iter().max_by_key(|m| m.score)
}

/// Holds the active rule set; swapped atomically on reload.
#[derive(Default)]
pub struct YaraEngine {
    current: RwLock<Option<Arc<RuleSet>>>,
    last_report: RwLock<Option<String>>,
}

impl YaraEngine {
    pub fn rules(&self) -> Option<Arc<RuleSet>> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn status_line(&self) -> Option<String> {
        self.last_report.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Load the precompiled cache if it matches the current sources; otherwise
    /// run `compile_fn` (normally a short-lived child process, so the compiler's
    /// ~170 MB peak never lands in the service) and load its output.
    pub fn load_or_compile(
        &self,
        dirs: &[PathBuf],
        compiled: &Path,
        compile_fn: impl FnOnce() -> Result<String>,
    ) -> Result<String> {
        let want = fingerprint(dirs);
        let (cached, stale): (Option<RuleSet>, Option<RuleSet>) = match RuleSet::load(compiled).ok() {
            Some(s) if s.version == want => (Some(s), None),
            other => (None, other),
        };
        let (set, line) = match cached {
            Some(set) => {
                let line = format!("{} rules (precompiled)", set.rule_count);
                (set, line)
            }
            None => {
                // Rules changed (or moved): protect with the previous compiled set
                // while the new one compiles, instead of running without YARA.
                if let Some(old) = stale.filter(|_| self.rules().is_none()) {
                    let note = format!("{} rules (updating…)", old.rule_count);
                    tracing::info!("YARA: using the previous compiled rules while recompiling");
                    *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(old));
                    *self.last_report.write().unwrap_or_else(|e| e.into_inner()) = Some(note);
                }
                let line = compile_fn()?;
                let set = RuleSet::load(compiled)?;
                (set, line)
            }
        };
        tracing::info!("YARA: {line}");
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(set));
        *self.last_report.write().unwrap_or_else(|e| e.into_inner()) = Some(line.clone());
        Ok(line)
    }

    pub fn set_error(&self, msg: String) {
        *self.last_report.write().unwrap_or_else(|e| e.into_inner()) = Some(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RULE: &str = r#"
rule Sentinel_Test_Marker {
  meta:
    description = "Harmless marker used by Vigil tests"
    score = 90
  strings:
    $m = "SENTINEL-LITE-YARA-TEST-MARKER"
  condition:
    $m
}
rule Unscored_Rule {
  strings:
    $m = "UNSCORED-MARKER"
  condition:
    $m
}"#;

    #[test]
    fn compiles_scans_and_reads_score() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.yar"), TEST_RULE).unwrap();
        std::fs::write(
            dir.path().join("broken.yar"),
            "rule x { condition: nonsense_identifier }",
        )
        .unwrap();
        let (set, report) = compile(&[dir.path().to_path_buf()]);
        let set = set.expect("valid file still loads");
        assert_eq!(set.rule_count, 2);
        assert_eq!(report.errors.len(), 1, "broken file reported");

        let hit = dir.path().join("sample.ps1");
        std::fs::write(&hit, b"junk SENTINEL-LITE-YARA-TEST-MARKER junk UNSCORED-MARKER").unwrap();
        let m = scan_file(&set, &hit).unwrap();
        let top = strongest(&m).unwrap();
        assert_eq!(top.rule, "Sentinel_Test_Marker");
        assert_eq!(top.score, 90);
        assert_eq!(top.namespace, "test");
        assert!(m.iter().any(|x| x.rule == "Unscored_Rule" && x.score == DEFAULT_SCORE));

        let clean = dir.path().join("clean.ps1");
        std::fs::write(&clean, b"Write-Host hello").unwrap();
        assert!(scan_file(&set, &clean).unwrap().is_empty());
    }

    #[test]
    fn version_changes_with_rule_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.yar"), TEST_RULE).unwrap();
        let v1 = compile(&[dir.path().to_path_buf()]).0.unwrap().version;
        std::fs::write(dir.path().join("a.yar"), TEST_RULE.replace("90", "95")).unwrap();
        let v2 = compile(&[dir.path().to_path_buf()]).0.unwrap().version;
        assert_ne!(v1, v2);
    }

    #[test]
    fn moving_the_rules_folder_keeps_the_fingerprint() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::write(a.path().join("t.yar"), TEST_RULE).unwrap();
        std::fs::write(b.path().join("t.yar"), TEST_RULE).unwrap();
        assert_eq!(fingerprint(&[a.path().to_path_buf()]), fingerprint(&[b.path().to_path_buf()]));
        std::fs::write(b.path().join("t.yar"), format!("{TEST_RULE}\n// edited")).unwrap();
        assert_ne!(fingerprint(&[a.path().to_path_buf()]), fingerprint(&[b.path().to_path_buf()]));
    }

    #[test]
    fn previous_rules_protect_while_recompiling() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("t.yar"), TEST_RULE).unwrap();
        let compiled = dir.path().join("compiled.bin");
        compile(std::slice::from_ref(&src)).0.unwrap().save(&compiled).unwrap();
        // The sources change, so the saved set is stale.
        std::fs::write(src.join("t.yar"), format!("{TEST_RULE}\n// new version")).unwrap();

        let engine = YaraEngine::default();
        let seen_during_compile = std::cell::Cell::new(None);
        let result = engine.load_or_compile(std::slice::from_ref(&src), &compiled, || {
            seen_during_compile.set(engine.rules().map(|r| r.rule_count));
            anyhow::bail!("compiler crashed")
        });
        assert!(result.is_err());
        assert_eq!(seen_during_compile.get(), Some(2), "old rules were not active during the compile");
        assert!(engine.rules().is_some(), "a failed recompile must not drop the working rules");
    }

    #[test]
    fn candidate_detection() {
        let dir = tempfile::tempdir().unwrap();
        let pe = dir.path().join("noext");
        std::fs::write(&pe, b"MZ\x90\x00rest").unwrap();
        let txt = dir.path().join("notes.txt");
        std::fs::write(&txt, b"hello world").unwrap();
        let ps = dir.path().join("x.PS1");
        std::fs::write(&ps, b"").unwrap();
        assert!(is_candidate(&pe));
        assert!(!is_candidate(&txt));
        assert!(is_candidate(&ps));
    }

    #[test]
    fn validate_rejects_garbage() {
        assert!(validate(TEST_RULE.as_bytes()).is_ok());
        assert!(validate(b"this is not yara").is_err());
    }
}
