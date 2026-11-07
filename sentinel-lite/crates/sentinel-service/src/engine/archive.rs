//! Look inside archives: ZIP (including Office OOXML, JAR, APK) and ISO 9660
//! disc images (with Joliet names). Malware is routinely delivered packed in
//! these so that the payload is only exposed after the user opens them.
//!
//! Members are read into memory and handed to a caller-supplied check (hash
//! lookup + YARA). Hard limits keep hostile archives harmless: total bytes
//! read, bytes per member, member count, compression ratio and nesting depth.
//! Member names are only used for reporting; nothing is extracted to disk.

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Total bytes read from all members of one archive (all nesting levels).
    pub max_total: u64,
    /// Members larger than this are skipped.
    pub max_member: u64,
    pub max_members: usize,
    /// Nested archives inside archives (1 = look one level deeper).
    pub max_depth: u8,
    /// Skip members whose uncompressed/compressed ratio exceeds this (zip bombs).
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total: 512 * 1024 * 1024,
            max_member: 64 * 1024 * 1024,
            max_members: 10_000,
            max_depth: 1,
            max_ratio: 200,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Iso,
}

/// Identify an archive by content (extensions lie).
pub fn kind_of_bytes(head: &[u8], iso_probe: Option<&[u8]>) -> Option<Kind> {
    if head.starts_with(b"PK\x03\x04") {
        return Some(Kind::Zip);
    }
    if iso_probe.is_some_and(|p| p.len() >= 6 && &p[1..6] == b"CD001") {
        return Some(Kind::Iso);
    }
    None
}

pub fn kind_of_file(path: &Path) -> Option<Kind> {
    let mut f = File::open(path).ok()?;
    let mut head = [0u8; 4];
    f.read_exact(&mut head).ok()?;
    let mut probe = [0u8; 6];
    let iso = f
        .seek(SeekFrom::Start(16 * 2048))
        .ok()
        .and_then(|_| f.read_exact(&mut probe).ok())
        .map(|_| &probe[..]);
    kind_of_bytes(&head, iso)
}

fn kind_of_memory(data: &[u8]) -> Option<Kind> {
    kind_of_bytes(&data[..data.len().min(4)], data.get(16 * 2048..16 * 2048 + 6))
}

/// What a member check returns when it matched.
pub struct Found<T> {
    /// "outer.iso/inner.zip/payload.exe"-style path inside the archive.
    pub member: String,
    pub detail: T,
}

#[derive(Default)]
pub struct Stats {
    pub members_checked: usize,
    pub members_skipped: usize,
    pub bytes_read: u64,
}

struct Walker<'a, T> {
    limits: Limits,
    stats: Stats,
    check: &'a mut dyn FnMut(&str, &[u8]) -> Option<T>,
}

impl<T> Walker<'_, T> {
    fn budget_left(&self) -> u64 {
        self.limits.max_total.saturating_sub(self.stats.bytes_read)
    }

    /// Check one member; recurse if it is itself an archive.
    fn member(&mut self, name: String, data: Vec<u8>, depth: u8) -> Result<Option<Found<T>>> {
        self.stats.members_checked += 1;
        self.stats.bytes_read += data.len() as u64;
        if let Some(detail) = (self.check)(&name, &data) {
            return Ok(Some(Found { member: name, detail }));
        }
        if depth < self.limits.max_depth {
            if let Some(kind) = kind_of_memory(&data) {
                let inner = match kind {
                    Kind::Zip => self.zip(std::io::Cursor::new(&data), &name, depth + 1),
                    Kind::Iso => self.iso(&mut std::io::Cursor::new(&data), &name, depth + 1),
                };
                match inner {
                    Ok(Some(found)) => return Ok(Some(found)),
                    Ok(None) => {}
                    Err(e) => tracing::debug!(member = %name, error = %format!("{e:#}"), "nested archive unreadable"),
                }
            }
        }
        Ok(None)
    }

    fn zip<R: Read + Seek>(&mut self, reader: R, prefix: &str, depth: u8) -> Result<Option<Found<T>>> {
        let mut zip = zip::ZipArchive::new(reader).context("not a readable zip")?;
        for i in 0..zip.len().min(self.limits.max_members) {
            if self.budget_left() == 0 {
                break;
            }
            let mut entry = match zip.by_index(i) {
                Ok(e) => e,
                Err(_) => {
                    // Typically an encrypted member: cannot be inspected.
                    self.stats.members_skipped += 1;
                    continue;
                }
            };
            if !entry.is_file() {
                continue;
            }
            let size = entry.size();
            let ratio = size / entry.compressed_size().max(1);
            if size == 0 || size > self.limits.max_member || size > self.budget_left() || ratio > self.limits.max_ratio
            {
                self.stats.members_skipped += 1;
                continue;
            }
            let name = format!("{prefix}/{}", entry.name());
            let mut data = Vec::with_capacity(size as usize);
            if entry.by_ref().take(size).read_to_end(&mut data).is_err() {
                self.stats.members_skipped += 1;
                continue;
            }
            drop(entry);
            if let Some(found) = self.member(name, data, depth)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn iso<R: Read + Seek>(&mut self, r: &mut R, prefix: &str, depth: u8) -> Result<Option<Found<T>>> {
        let (root_lba, root_len, joliet) = iso_root(r)?;
        // Breadth-first over directories; `seen` stops directory loops.
        let mut queue = vec![(root_lba, root_len, String::new())];
        let mut seen = std::collections::HashSet::new();
        let mut members = 0usize;
        while let Some((lba, len, dir_path)) = queue.pop() {
            if !seen.insert(lba) || len > 16 * 1024 * 1024 {
                continue;
            }
            let dir = read_extent(r, lba, len)?;
            let mut off = 0usize;
            while off < dir.len() {
                let rec_len = dir[off] as usize;
                if rec_len == 0 {
                    // Records never span sectors: skip to the next one.
                    off = (off / 2048 + 1) * 2048;
                    continue;
                }
                if off + rec_len > dir.len() || rec_len < 34 {
                    break;
                }
                let rec = &dir[off..off + rec_len];
                off += rec_len;
                let extent = u32::from_le_bytes(rec[2..6].try_into().unwrap()) as u64;
                let size = u32::from_le_bytes(rec[10..14].try_into().unwrap()) as u64;
                let is_dir = rec[25] & 0x02 != 0;
                let name_len = rec[32] as usize;
                let raw_name = rec.get(33..33 + name_len).unwrap_or_default();
                if raw_name == [0] || raw_name == [1] {
                    continue; // "." and ".."
                }
                let name = decode_iso_name(raw_name, joliet);
                let path = if dir_path.is_empty() {
                    name
                } else {
                    format!("{dir_path}/{name}")
                };
                if is_dir {
                    queue.push((extent, size, path));
                    continue;
                }
                members += 1;
                if members > self.limits.max_members || self.budget_left() == 0 {
                    return Ok(None);
                }
                if size == 0 || size > self.limits.max_member || size > self.budget_left() {
                    self.stats.members_skipped += 1;
                    continue;
                }
                let data = read_extent(r, extent, size)?;
                if let Some(found) = self.member(format!("{prefix}/{path}"), data, depth)? {
                    return Ok(Some(found));
                }
            }
        }
        Ok(None)
    }
}

fn read_extent<R: Read + Seek>(r: &mut R, lba: u64, len: u64) -> Result<Vec<u8>> {
    r.seek(SeekFrom::Start(lba * 2048))?;
    let mut buf = Vec::with_capacity(len as usize);
    r.take(len).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Root directory (LBA, length) and whether it comes from a Joliet descriptor.
fn iso_root<R: Read + Seek>(r: &mut R) -> Result<(u64, u64, bool)> {
    let mut primary = None;
    for sector in 16..64u64 {
        let mut vd = [0u8; 2048];
        r.seek(SeekFrom::Start(sector * 2048))?;
        if r.read_exact(&mut vd).is_err() || &vd[1..6] != b"CD001" {
            break;
        }
        let root = &vd[156..156 + 34];
        let lba = u32::from_le_bytes(root[2..6].try_into().unwrap()) as u64;
        let len = u32::from_le_bytes(root[10..14].try_into().unwrap()) as u64;
        match vd[0] {
            1 => primary = Some((lba, len, false)),
            // Supplementary descriptor with a UCS-2 escape sequence = Joliet (long names).
            2 if vd[88] == b'%' && vd[89] == b'/' && matches!(vd[90], b'@' | b'C' | b'E') => {
                return Ok((lba, len, true))
            }
            255 => break,
            _ => {}
        }
    }
    match primary {
        Some(p) => Ok(p),
        None => bail!("no ISO 9660 primary volume descriptor"),
    }
}

fn decode_iso_name(raw: &[u8], joliet: bool) -> String {
    let name = if joliet {
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    // Strip the ";1" version suffix.
    name.split(';').next().unwrap_or_default().to_string()
}

/// Walk `path` (a ZIP or ISO); returns the first member for which `check` matched.
pub fn scan<T>(
    path: &Path,
    limits: Limits,
    check: &mut dyn FnMut(&str, &[u8]) -> Option<T>,
) -> Result<(Option<Found<T>>, Stats)> {
    let kind = kind_of_file(path).context("not a supported archive")?;
    let display = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut w = Walker {
        limits,
        stats: Stats::default(),
        check,
    };
    let mut f = File::open(path)?;
    let found = match kind {
        Kind::Zip => w.zip(&mut f, &display, 0)?,
        Kind::Iso => w.iso(&mut f, &display, 0)?,
    };
    Ok((found, w.stats))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Write;

    pub fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default();
            for (name, data) in files {
                z.start_file(*name, opts).unwrap();
                z.write_all(data).unwrap();
            }
            z.finish().unwrap();
        }
        buf.into_inner()
    }

    /// Minimal single-directory ISO 9660 image (optionally with a Joliet descriptor).
    pub fn make_iso(files: &[(&str, &[u8])], joliet: bool) -> Vec<u8> {
        const S: usize = 2048;
        let dir_lba = 20usize;
        let mut data_lba = 21usize;
        let mut img = vec![0u8; S * dir_lba]; // sectors 0..dir_lba; the directory follows at dir_lba
        let mut dir = Vec::new();
        let rec = |dir: &mut Vec<u8>, lba: u32, size: u32, flags: u8, name: &[u8]| {
            let len = 33 + name.len() + (name.len() + 1) % 2;
            let mut r = vec![0u8; len];
            r[0] = len as u8;
            r[2..6].copy_from_slice(&lba.to_le_bytes());
            r[10..14].copy_from_slice(&size.to_le_bytes());
            r[25] = flags;
            r[32] = name.len() as u8;
            r[33..33 + name.len()].copy_from_slice(name);
            dir.extend_from_slice(&r);
        };
        rec(&mut dir, dir_lba as u32, S as u32, 2, &[0]);
        rec(&mut dir, dir_lba as u32, S as u32, 2, &[1]);
        let mut payload = Vec::new();
        for (name, content) in files {
            let encoded: Vec<u8> = if joliet {
                name.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
            } else {
                format!("{};1", name.to_uppercase()).into_bytes()
            };
            rec(&mut dir, data_lba as u32, content.len() as u32, 0, &encoded);
            let mut padded = content.to_vec();
            padded.resize(content.len().div_ceil(S).max(1) * S, 0);
            data_lba += padded.len() / S;
            payload.extend_from_slice(&padded);
        }
        dir.resize(S, 0);
        let mut vd = |sector: usize, kind: u8| {
            let o = sector * S;
            img[o] = kind;
            img[o + 1..o + 6].copy_from_slice(b"CD001");
            if kind == 2 {
                img[o + 88..o + 91].copy_from_slice(b"%/E");
            }
            if kind != 255 {
                let root = o + 156;
                img[root] = 34;
                img[root + 2..root + 6].copy_from_slice(&(dir_lba as u32).to_le_bytes());
                img[root + 10..root + 14].copy_from_slice(&(S as u32).to_le_bytes());
                img[root + 25] = 2;
            }
        };
        vd(16, 1);
        if joliet {
            vd(17, 2);
            vd(18, 255);
        } else {
            vd(17, 255);
        }
        img.extend_from_slice(&dir);
        img.extend_from_slice(&payload);
        img
    }

    fn find(path: &Path, needle: &'static [u8]) -> Option<String> {
        let mut check = |_: &str, data: &[u8]| data.windows(needle.len()).any(|w| w == needle).then_some(());
        scan(path, Limits::default(), &mut check).unwrap().0.map(|f| f.member)
    }

    #[test]
    fn finds_member_in_zip_and_nested_zip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("invoice.zip");
        std::fs::write(
            &p,
            make_zip(&[("readme.txt", b"hello"), ("docs/invoice.exe", b"MZ..BADBAD..")]),
        )
        .unwrap();
        assert_eq!(find(&p, b"BADBAD").as_deref(), Some("invoice.zip/docs/invoice.exe"));

        let inner = make_zip(&[("payload.js", b"var x = 'BADBAD';")]);
        let p2 = dir.path().join("outer.zip");
        std::fs::write(&p2, make_zip(&[("inner.zip", &inner)])).unwrap();
        assert_eq!(find(&p2, b"BADBAD").as_deref(), Some("outer.zip/inner.zip/payload.js"));
        assert!(find(&p2, b"NOPE").is_none());
    }

    #[test]
    fn finds_member_in_iso_with_and_without_joliet() {
        let dir = tempfile::tempdir().unwrap();
        for joliet in [false, true] {
            let p = dir.path().join(format!("delivery-{joliet}.iso"));
            std::fs::write(
                &p,
                make_iso(&[("Document.lnk", b"shortcut"), ("Setup.exe", b"MZ BADBAD")], joliet),
            )
            .unwrap();
            assert_eq!(kind_of_file(&p), Some(Kind::Iso));
            let member = find(&p, b"BADBAD").unwrap();
            let expected = if joliet { "Setup.exe" } else { "SETUP.EXE" };
            assert!(member.ends_with(expected), "{member}");
        }
    }

    #[test]
    fn zip_inside_iso_is_followed_one_level_but_not_two() {
        let dir = tempfile::tempdir().unwrap();
        let zip1 = make_zip(&[("x.exe", b"BADBAD")]);
        let p = dir.path().join("a.iso");
        std::fs::write(&p, make_iso(&[("files.zip", &zip1)], true)).unwrap();
        assert!(find(&p, b"BADBAD").is_some());

        let zip2 = make_zip(&[("level2.zip", &zip1)]);
        let p = dir.path().join("b.iso");
        std::fs::write(&p, make_iso(&[("files.zip", &zip2)], true)).unwrap();
        assert!(find(&p, b"BADBAD").is_none(), "depth limit");
    }

    #[test]
    fn hostile_archives_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        // Highly compressible member: ratio guard skips it instead of inflating.
        let bomb = vec![0u8; 50 * 1024 * 1024];
        let p = dir.path().join("bomb.zip");
        {
            let f = File::create(&p).unwrap();
            let mut z = zip::ZipWriter::new(f);
            let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            z.start_file("zeros.bin", opts).unwrap();
            z.write_all(&bomb).unwrap();
            z.finish().unwrap();
        }
        let mut calls = 0;
        let mut check = |_: &str, _: &[u8]| {
            calls += 1;
            None::<()>
        };
        let (_, stats) = scan(&p, Limits::default(), &mut check).unwrap();
        assert_eq!(calls, 0);
        assert_eq!(stats.members_skipped, 1);

        // Garbage that claims to be an ISO must error, not loop or panic.
        let p = dir.path().join("bad.iso");
        let mut img = vec![0u8; 18 * 2048];
        img[16 * 2048 + 1..16 * 2048 + 6].copy_from_slice(b"CD001");
        img[16 * 2048] = 1;
        img[16 * 2048 + 156 + 2..16 * 2048 + 156 + 6].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&p, img).unwrap();
        let mut check = |_: &str, _: &[u8]| None::<()>;
        let _ = scan(&p, Limits::default(), &mut check); // Ok or Err, but returns
    }
}
