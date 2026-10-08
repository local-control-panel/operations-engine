//! A bounded, streaming reader for the gzip'd tar archives
//! `wordpress.migrateExport` produces, extracting into a `ManagedRoot`
//! (fd-relative, so no path or symlink can lead outside it).
//!
//! It accepts what GNU `tar --create` writes for a real directory tree:
//! regular files, directories and symlinks, with GNU long-name (`L`/`K`)
//! and POSIX PAX (`x`/`g`) extension headers and base-256 sizes. It refuses
//! everything else before writing it: hardlinks, devices, FIFOs, unknown
//! entry types, absolute names, `..` components, and symlinks whose target
//! is absolute or leaves the root. Symlinks are created only after every
//! other entry, so no file is ever written through one. Regular files get
//! their archived permission bits without setuid/setgid/sticky; ownership is
//! left to the caller. `Limits` caps the entry count and the total file
//! bytes, checked before each entry is written. Modification times are
//! restored (second precision from the header, finer when a PAX `mtime`
//! record carries it) on files, symlinks and directories; directories last,
//! after everything created inside them. A time that cannot be set is skipped.

use std::{
    ffi::OsStr,
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use crate::{
    filesystem::ManagedRoot, site::SiteRelativePath, wordpress_migrate_export::symlink_stays_inside,
};

const BLOCK: usize = 512;
/// Longest GNU long-name / long-link / PAX record this reader accepts.
const MAX_META_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_entries: u64,
    pub max_file_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub entries: u64,
    pub file_bytes: u64,
    pub symlinks: u64,
}

#[derive(Debug)]
pub enum ExtractError {
    Io(io::Error),
    Corrupt(&'static str),
    /// An entry this reader refuses, with its archived name.
    Unsafe(String),
    TooManyEntries,
    TooLarge,
}

impl From<io::Error> for ExtractError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn extract(
    reader: impl Read,
    dest: &ManagedRoot,
    limits: Limits,
) -> Result<Summary, ExtractError> {
    let mut reader = reader;
    let mut summary = Summary::default();
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut pax_size: Option<u64> = None;
    let mut pax_mtime: Option<(i64, u32)> = None;
    let mut dir_times: Vec<(SiteRelativePath, (i64, u32))> = Vec::new();
    let mut symlinks: Vec<(SiteRelativePath, PathBuf, Option<(i64, u32)>)> = Vec::new();
    let mut header = [0u8; BLOCK];

    loop {
        if !read_block(&mut reader, &mut header)? {
            return Err(ExtractError::Corrupt("archive ends without an end marker"));
        }
        if header.iter().all(|&b| b == 0) {
            break;
        }
        verify_checksum(&header)?;
        let typeflag = header[156];
        let size = match pax_size.take() {
            Some(size) => size,
            None => parse_numeric(&header[124..136])?,
        };

        match typeflag {
            b'L' | b'K' | b'x' | b'g' => {
                if size > MAX_META_BYTES {
                    return Err(ExtractError::Corrupt("oversized extension header"));
                }
                let data = read_data(&mut reader, size)?;
                match typeflag {
                    b'L' => long_name = Some(trim_nul(&data).to_vec()),
                    b'K' => long_link = Some(trim_nul(&data).to_vec()),
                    b'x' => {
                        let records = parse_pax(&data)?;
                        if let Some(path) = records.path {
                            long_name = Some(path);
                        }
                        if let Some(link) = records.linkpath {
                            long_link = Some(link);
                        }
                        pax_size = records.size;
                        if records.mtime.is_some() {
                            pax_mtime = records.mtime;
                        }
                    }
                    _ => {} // Global PAX defaults: nothing this reader uses.
                }
                continue;
            }
            _ => {}
        }

        let raw_name = long_name.take().unwrap_or_else(|| header_name(&header));
        let raw_link = long_link
            .take()
            .unwrap_or_else(|| field(&header[157..257]).to_vec());
        let display = String::from_utf8_lossy(&raw_name).into_owned();
        let mtime = pax_mtime
            .take()
            .or_else(|| parse_numeric(&header[136..148]).ok().map(|s| (s as i64, 0)));

        summary.entries += 1;
        if summary.entries > limits.max_entries {
            return Err(ExtractError::TooManyEntries);
        }
        let name = match entry_path(&raw_name) {
            Some(name) => name,
            None => return Err(ExtractError::Unsafe(display)),
        };

        match typeflag {
            b'0' | b'\0' | b'7' => {
                let Some(name) = name else {
                    return Err(ExtractError::Unsafe(display));
                };
                summary.file_bytes = summary.file_bytes.saturating_add(size);
                if summary.file_bytes > limits.max_file_bytes {
                    return Err(ExtractError::TooLarge);
                }
                if let Some(parent) = parent_of(&name) {
                    dest.create_dir_all(&parent)?;
                }
                let mut file = dest.create_new_file(&name)?;
                copy_exact(&mut reader, &mut file, size)?;
                skip_padding(&mut reader, size)?;
                let mode = parse_numeric(&header[100..108])? as u32 & 0o777;
                dest.set_mode(&name, mode)?;
                if let Some((secs, nanos)) = mtime {
                    let _ = dest.set_modified_nofollow(&name, secs, nanos);
                }
            }
            b'5' => {
                if size != 0 {
                    return Err(ExtractError::Corrupt("a directory entry carries data"));
                }
                if let Some(name) = name {
                    dest.create_dir_all(&name)?;
                    if let Some(time) = mtime {
                        dir_times.push((name, time));
                    }
                }
            }
            b'2' => {
                let Some(name) = name else {
                    return Err(ExtractError::Unsafe(display));
                };
                let target = PathBuf::from(OsStr::from_bytes(&raw_link));
                if raw_link.is_empty() || !symlink_stays_inside(name.as_path(), &target) {
                    return Err(ExtractError::Unsafe(display));
                }
                skip_data(&mut reader, size)?;
                summary.symlinks += 1;
                symlinks.push((name, target, mtime));
            }
            _ => return Err(ExtractError::Unsafe(display)),
        }
    }

    for (link, target, mtime) in symlinks {
        if let Some(parent) = parent_of(&link) {
            dest.create_dir_all(&parent)?;
        }
        dest.symlink_relative(&link, &target)?;
        if let Some((secs, nanos)) = mtime {
            let _ = dest.set_modified_nofollow(&link, secs, nanos);
        }
    }
    // Deepest first: setting a child's time must not disturb its parent's.
    for (dir, (secs, nanos)) in dir_times.into_iter().rev() {
        let _ = dest.set_modified_nofollow(&dir, secs, nanos);
    }
    Ok(summary)
}

/// `Some(None)` for the archive root itself (`.`/`./`), `Some(Some(path))`
/// for a safe relative path, `None` for anything absolute or with `..`.
fn entry_path(raw: &[u8]) -> Option<Option<SiteRelativePath>> {
    let path = Path::new(OsStr::from_bytes(raw));
    if raw.is_empty() || path.is_absolute() || raw.contains(&0) {
        return None;
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if clean.as_os_str().is_empty() {
        return Some(None);
    }
    SiteRelativePath::parse(&clean).ok().map(Some)
}

fn parent_of(path: &SiteRelativePath) -> Option<SiteRelativePath> {
    path.as_path()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .and_then(|parent| SiteRelativePath::parse(parent).ok())
}

fn header_name(header: &[u8; BLOCK]) -> Vec<u8> {
    let name = field(&header[0..100]);
    // ustar: a non-empty prefix is joined with '/'.
    if &header[257..262] == b"ustar" {
        let prefix = field(&header[345..500]);
        if !prefix.is_empty() {
            let mut joined = prefix.to_vec();
            joined.push(b'/');
            joined.extend_from_slice(name);
            return joined;
        }
    }
    name.to_vec()
}

fn field(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |index| index + 1);
    &bytes[..end]
}

/// Octal (NUL/space padded), or GNU base-256 when the high bit is set.
fn parse_numeric(bytes: &[u8]) -> Result<u64, ExtractError> {
    if bytes[0] & 0x80 != 0 {
        if bytes[0] & 0x40 != 0 {
            return Err(ExtractError::Corrupt("negative numeric field"));
        }
        let mut value: u64 = u64::from(bytes[0] & 0x3f);
        for &byte in &bytes[1..] {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(byte)))
                .ok_or(ExtractError::Corrupt("numeric field overflows"))?;
        }
        return Ok(value);
    }
    let text = bytes
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|&b| b != 0 && b != b' ');
    let mut value: u64 = 0;
    for byte in text {
        if !(b'0'..=b'7').contains(&byte) {
            return Err(ExtractError::Corrupt("bad octal field"));
        }
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or(ExtractError::Corrupt("numeric field overflows"))?;
    }
    Ok(value)
}

fn verify_checksum(header: &[u8; BLOCK]) -> Result<(), ExtractError> {
    let stored = parse_numeric(&header[148..156])?;
    let computed: u64 = header
        .iter()
        .enumerate()
        .map(|(index, &byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(byte)
            }
        })
        .sum();
    if stored == computed {
        Ok(())
    } else {
        Err(ExtractError::Corrupt("header checksum mismatch"))
    }
}

#[derive(Default)]
struct PaxRecords {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<u64>,
    mtime: Option<(i64, u32)>,
}

/// `"<seconds>[.<fraction>]"` as PAX writes it; a bad value is ignored.
fn parse_pax_time(value: &[u8]) -> Option<(i64, u32)> {
    let text = std::str::from_utf8(value).ok()?;
    let (secs, fraction) = text.split_once('.').unwrap_or((text, ""));
    let secs: i64 = secs.parse().ok()?;
    if secs < 0 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits: String = fraction
        .chars()
        .chain("000000000".chars())
        .take(9)
        .collect();
    Some((secs, digits.parse().ok()?))
}

/// `"<len> <key>=<value>\n"` records.
fn parse_pax(mut data: &[u8]) -> Result<PaxRecords, ExtractError> {
    let mut records = PaxRecords::default();
    while !data.is_empty() {
        let space = data
            .iter()
            .position(|&b| b == b' ')
            .ok_or(ExtractError::Corrupt("bad PAX record"))?;
        let length: usize = std::str::from_utf8(&data[..space])
            .ok()
            .and_then(|text| text.parse().ok())
            .filter(|&length| length > space + 1 && length <= data.len())
            .ok_or(ExtractError::Corrupt("bad PAX record length"))?;
        let record = &data[space + 1..length];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        let equals = record
            .iter()
            .position(|&b| b == b'=')
            .ok_or(ExtractError::Corrupt("bad PAX record"))?;
        let (key, value) = (&record[..equals], &record[equals + 1..]);
        match key {
            b"path" => records.path = Some(value.to_vec()),
            b"linkpath" => records.linkpath = Some(value.to_vec()),
            b"size" => {
                records.size = Some(
                    std::str::from_utf8(value)
                        .ok()
                        .and_then(|text| text.parse().ok())
                        .ok_or(ExtractError::Corrupt("bad PAX size"))?,
                );
            }
            b"mtime" => records.mtime = parse_pax_time(value),
            _ => {}
        }
        data = &data[length..];
    }
    Ok(records)
}

/// Reads one block; `false` at a clean end of input.
fn read_block(reader: &mut impl Read, block: &mut [u8; BLOCK]) -> Result<bool, ExtractError> {
    let mut filled = 0;
    while filled < BLOCK {
        let read = reader.read(&mut block[filled..])?;
        if read == 0 {
            return if filled == 0 {
                Ok(false)
            } else {
                Err(ExtractError::Corrupt("truncated header"))
            };
        }
        filled += read;
    }
    Ok(true)
}

fn read_data(reader: &mut impl Read, size: u64) -> Result<Vec<u8>, ExtractError> {
    let mut data = Vec::with_capacity(size as usize);
    copy_exact(reader, &mut data, size)?;
    skip_padding(reader, size)?;
    Ok(data)
}

fn copy_exact(
    reader: &mut impl Read,
    writer: &mut impl Write,
    size: u64,
) -> Result<(), ExtractError> {
    let copied = io::copy(&mut reader.take(size), writer)?;
    if copied != size {
        return Err(ExtractError::Corrupt("truncated entry data"));
    }
    Ok(())
}

fn skip_data(reader: &mut impl Read, size: u64) -> Result<(), ExtractError> {
    copy_exact(reader, &mut io::sink(), size)?;
    skip_padding(reader, size)
}

fn skip_padding(reader: &mut impl Read, size: u64) -> Result<(), ExtractError> {
    let padding = (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64;
    copy_exact(reader, &mut io::sink(), padding)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use flate2::{Compression, read::GzDecoder, write::GzEncoder};

    use super::*;
    use crate::site::TrustedRoot;

    const LIMITS: Limits = Limits {
        max_entries: 100,
        max_file_bytes: 1024 * 1024,
    };

    const ARCHIVED_MTIME: u64 = 1_700_000_000;

    fn mtime(path: &Path) -> (i64, i64) {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path).unwrap();
        (meta.mtime(), meta.mtime_nsec())
    }

    fn header(name: &str, typeflag: u8, size: u64, mode: u32, link: &str) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        block[..name.len()].copy_from_slice(name.as_bytes());
        block[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
        block[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        block[136..147].copy_from_slice(format!("{ARCHIVED_MTIME:011o}").as_bytes());
        block[156] = typeflag;
        block[157..157 + link.len()].copy_from_slice(link.as_bytes());
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        block[148..156].copy_from_slice(b"        ");
        let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
        block[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        block
    }

    struct Archive(Vec<u8>);

    impl Archive {
        fn new() -> Self {
            Self(Vec::new())
        }
        fn entry(mut self, name: &str, typeflag: u8, data: &[u8], mode: u32, link: &str) -> Self {
            self.0
                .extend_from_slice(&header(name, typeflag, data.len() as u64, mode, link));
            self.0.extend_from_slice(data);
            let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
            self.0.extend(std::iter::repeat_n(0, pad));
            self
        }
        fn file(self, name: &str, data: &[u8]) -> Self {
            self.entry(name, b'0', data, 0o644, "")
        }
        fn end(mut self) -> Vec<u8> {
            self.0.extend_from_slice(&[0u8; BLOCK * 2]);
            self.0
        }
    }

    fn dest() -> (tempfile::TempDir, ManagedRoot, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap();
        let root = ManagedRoot::open(&TrustedRoot::parse(&path).unwrap()).unwrap();
        (dir, root, path)
    }

    fn run(bytes: &[u8]) -> (Result<Summary, ExtractError>, PathBuf, tempfile::TempDir) {
        let (dir, root, path) = dest();
        (extract(bytes, &root, LIMITS), path, dir)
    }

    #[test]
    fn extracts_files_directories_and_inside_symlinks() {
        let archive = Archive::new()
            .entry("./", b'5', b"", 0o755, "")
            .entry("./wp-content/", b'5', b"", 0o755, "")
            .file("./index.php", b"<?php")
            .entry("./wp-content/run.sh", b'0', b"#!/bin/sh", 0o4755, "")
            .entry("./wp-content/link.php", b'2', b"", 0o777, "../index.php")
            .end();
        let (result, path, _dir) = run(&archive);
        let summary = result.unwrap();
        assert_eq!(
            summary,
            Summary {
                entries: 5,
                file_bytes: 14,
                symlinks: 1
            }
        );
        assert_eq!(fs::read(path.join("index.php")).unwrap(), b"<?php");
        let mode = fs::metadata(path.join("wp-content/run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o755, "setuid is stripped");
        assert_eq!(
            fs::read_link(path.join("wp-content/link.php")).unwrap(),
            Path::new("../index.php")
        );
    }

    #[test]
    fn restores_modification_times_on_files_symlinks_and_directories() {
        let archive = Archive::new()
            .entry("./", b'5', b"", 0o755, "")
            .entry("./sub/", b'5', b"", 0o755, "")
            .file("./sub/index.php", b"<?php")
            .entry("./sub/link.php", b'2', b"", 0o777, "index.php")
            .end();
        let (result, path, _dir) = run(&archive);
        result.unwrap();
        let expected = (ARCHIVED_MTIME as i64, 0);
        assert_eq!(mtime(&path.join("sub/index.php")), expected);
        assert_eq!(
            mtime(&path.join("sub/link.php")),
            expected,
            "the link itself"
        );
        assert_eq!(
            mtime(&path.join("sub")),
            expected,
            "set after the entries created inside it"
        );
        assert_eq!(
            mtime(&path.join("sub/index.php")),
            expected,
            "a symlink's time does not change its target"
        );
    }

    #[test]
    fn a_pax_mtime_record_carries_the_fraction() {
        let body = "30 mtime=1700000000.123456789\n";
        assert_eq!(body.len(), 30);
        let archive = Archive::new()
            .entry("PaxHeaders/x", b'x', body.as_bytes(), 0o644, "")
            .file("precise.php", b"x")
            .file("plain.php", b"x")
            .end();
        let (result, path, _dir) = run(&archive);
        result.unwrap();
        assert_eq!(
            mtime(&path.join("precise.php")),
            (ARCHIVED_MTIME as i64, 123_456_789)
        );
        assert_eq!(
            mtime(&path.join("plain.php")),
            (ARCHIVED_MTIME as i64, 0),
            "the record applies to one entry only"
        );
        assert_eq!(parse_pax_time(b"12.5"), Some((12, 500_000_000)));
        assert_eq!(parse_pax_time(b"-1"), None);
        assert_eq!(parse_pax_time(b"1.x"), None);
    }

    #[test]
    fn refuses_unsafe_entries() {
        for (name, typeflag, link) in [
            ("../escape.php", b'0', ""),
            ("/etc/passwd", b'0', ""),
            ("a/../../escape", b'0', ""),
            ("hard", b'1', "index.php"),
            ("pipe", b'6', ""),
            ("dev", b'3', ""),
            ("link", b'2', "../../etc/passwd"),
            ("link", b'2', "/etc/passwd"),
        ] {
            let archive = Archive::new().entry(name, typeflag, b"", 0o644, link).end();
            let (result, path, _dir) = run(&archive);
            assert!(
                matches!(result, Err(ExtractError::Unsafe(_))),
                "{name} {typeflag}"
            );
            assert_eq!(
                fs::read_dir(&path).unwrap().count(),
                0,
                "{name}: nothing written"
            );
        }
    }

    #[test]
    fn symlinks_are_created_last_so_no_file_lands_through_one() {
        // `dir` arrives as a symlink before a file that would go under it.
        let archive = Archive::new()
            .entry("dir", b'2', b"", 0o777, "real")
            .entry("real/", b'5', b"", 0o755, "")
            .file("dir/x.php", b"x")
            .end();
        let (result, path, _dir) = run(&archive);
        // `dir/x.php` made `dir` a real directory, so the symlink cannot be
        // created afterwards: the archive is rejected, never written through.
        assert!(matches!(result, Err(ExtractError::Io(_))));
        assert!(fs::symlink_metadata(path.join("dir")).unwrap().is_dir());
    }

    #[test]
    fn enforces_entry_and_size_limits() {
        let mut many = Archive::new();
        for index in 0..=LIMITS.max_entries {
            many = many.file(&format!("f{index}"), b"");
        }
        let (result, _path, _dir) = run(&many.end());
        assert!(matches!(result, Err(ExtractError::TooManyEntries)));

        let big = vec![0u8; LIMITS.max_file_bytes as usize + 1];
        let (result, path, _dir) = run(&Archive::new().file("big", &big).end());
        assert!(matches!(result, Err(ExtractError::TooLarge)));
        assert!(!path.join("big").exists());
    }

    #[test]
    fn rejects_corrupt_or_truncated_archives() {
        let mut archive = Archive::new().file("a", b"data").end();
        archive[0] = b'b';
        let (result, _p, _d) = run(&archive);
        assert!(matches!(result, Err(ExtractError::Corrupt(_))));

        let mut truncated = Archive::new().file("a", b"data").end();
        truncated.truncate(BLOCK + 10);
        let (result, _p, _d) = run(&truncated);
        assert!(matches!(result, Err(ExtractError::Corrupt(_))));

        let no_end = Archive::new().file("a", b"data").0;
        let (result, _p, _d) = run(&no_end);
        assert!(matches!(result, Err(ExtractError::Corrupt(_))));
    }

    #[test]
    fn reads_gnu_long_names_pax_paths_and_base256_sizes() {
        let long = format!("{}/file.php", "d".repeat(150));
        let mut long_data = long.clone().into_bytes();
        long_data.push(0);
        let pax_name = format!("{}/pax.php", "p".repeat(120));
        let record_body = format!(" path={pax_name}\n");
        let mut length = record_body.len() + 1;
        let record = loop {
            let candidate = format!("{length}{record_body}");
            if candidate.len() == length {
                break candidate;
            }
            length = candidate.len();
        };
        let archive = Archive::new()
            .entry("././@LongLink", b'L', &long_data, 0o644, "")
            .file("truncated-name", b"long")
            .entry("PaxHeaders/x", b'x', record.as_bytes(), 0o644, "")
            .file("short", b"pax")
            .end();
        let (result, path, _dir) = run(&archive);
        result.unwrap();
        assert_eq!(fs::read(path.join(&long)).unwrap(), b"long");
        assert_eq!(fs::read(path.join(&pax_name)).unwrap(), b"pax");

        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[11] = 0x02;
        field[10] = 0x01;
        assert_eq!(parse_numeric(&field).unwrap(), 0x0102);
    }

    #[test]
    fn round_trips_an_archive_made_by_the_system_tar() {
        let source = tempfile::tempdir().unwrap();
        let src = source.path();
        let deep = src.join("wp-content/uploads/".to_owned() + &"x".repeat(110));
        fs::create_dir_all(&deep).unwrap();
        fs::write(src.join("index.php"), "<?php").unwrap();
        fs::write(deep.join("image.jpg"), vec![7u8; 5000]).unwrap();
        std::os::unix::fs::symlink("../index.php", src.join("wp-content/alias.php")).unwrap();
        let archive = source.path().join("..").join(format!(
            "{}.tar",
            source.path().file_name().unwrap().to_string_lossy()
        ));
        let status = std::process::Command::new("tar")
            .args(["--create", "--file"])
            .arg(&archive)
            .arg("--directory")
            .arg(src)
            .arg(".")
            .status()
            .unwrap();
        assert!(status.success());
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&fs::read(&archive).unwrap()).unwrap();
        let compressed = gz.finish().unwrap();
        fs::remove_file(&archive).unwrap();

        let (_dir, root, path) = dest();
        let summary = extract(GzDecoder::new(&compressed[..]), &root, LIMITS).unwrap();
        assert_eq!(summary.symlinks, 1);
        assert_eq!(fs::read(path.join("index.php")).unwrap(), b"<?php");
        let rel = deep.strip_prefix(src).unwrap();
        assert_eq!(
            fs::read(path.join(rel).join("image.jpg")).unwrap().len(),
            5000
        );
        assert_eq!(
            fs::read_link(path.join("wp-content/alias.php")).unwrap(),
            Path::new("../index.php")
        );
    }
}
