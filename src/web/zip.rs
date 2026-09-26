//! "Download all": the files of a run as one stored (uncompressed) ZIP, streamed. CRCs are
//! computed in a first pass so no data descriptors are needed; ZIP64 records are written only
//! when a size or offset needs them.

use super::http::Response;
use super::runs::{Run, list_files};
use std::io::{Read, Write};
use std::sync::Arc;

fn dos_time(t: std::time::SystemTime) -> (u16, u16) {
    let secs = t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // civil from days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let y = y.clamp(1980, 2107);
    let time = ((rem / 3600) << 11) | (((rem % 3600) / 60) << 5) | ((rem % 60) / 2);
    let date = ((y - 1980) << 9) | (m << 5) | d;
    (time as u16, date as u16)
}

fn crc_of(p: &std::path::Path) -> std::io::Result<(u32, u64)> {
    let mut f = std::fs::File::open(p)?;
    let mut buf = vec![0u8; 1 << 20];
    let mut crc = 0u32;
    let mut n = 0u64;
    loop {
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        crc = crate::codecs::crc::crc32_update(crc, &buf[..k]);
        n += k as u64;
    }
    Ok((crc, n))
}

struct Entry {
    name: String,
    crc: u32,
    size: u64,
    offset: u64,
    time: u16,
    date: u16,
}

fn le16(o: &mut Vec<u8>, v: u16) {
    o.extend_from_slice(&v.to_le_bytes());
}
fn le32(o: &mut Vec<u8>, v: u32) {
    o.extend_from_slice(&v.to_le_bytes());
}
fn le64(o: &mut Vec<u8>, v: u64) {
    o.extend_from_slice(&v.to_le_bytes());
}

const FF: u32 = 0xffff_ffff;

/// Write a stored ZIP of `files` (name, path) into `w`.
pub fn write_zip(w: &mut dyn Write, files: &[(String, std::path::PathBuf)]) -> std::io::Result<()> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut off = 0u64;
    for (name, path) in files {
        let (crc, size) = crc_of(path)?;
        let (time, date) = dos_time(std::fs::metadata(path).and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH));
        let z64 = size >= FF as u64;
        let mut h = Vec::with_capacity(64 + name.len());
        le32(&mut h, 0x04034b50);
        le16(&mut h, if z64 { 45 } else { 20 });
        le16(&mut h, 0x0800);
        le16(&mut h, 0);
        le16(&mut h, time);
        le16(&mut h, date);
        le32(&mut h, crc);
        le32(&mut h, if z64 { FF } else { size as u32 });
        le32(&mut h, if z64 { FF } else { size as u32 });
        le16(&mut h, name.len() as u16);
        le16(&mut h, if z64 { 20 } else { 0 });
        h.extend_from_slice(name.as_bytes());
        if z64 {
            le16(&mut h, 1);
            le16(&mut h, 16);
            le64(&mut h, size);
            le64(&mut h, size);
        }
        w.write_all(&h)?;
        let copied = std::io::copy(&mut std::fs::File::open(path)?.take(size), w)?;
        if copied != size {
            return Err(std::io::Error::other("file changed while zipping"));
        }
        entries.push(Entry { name: name.clone(), crc, size, offset: off, time, date });
        off += h.len() as u64 + size;
    }
    let cd_start = off;
    let mut cd = Vec::new();
    for e in &entries {
        let big_size = e.size >= FF as u64;
        let big_off = e.offset >= FF as u64;
        let mut extra = Vec::new();
        if big_size || big_off {
            le16(&mut extra, 1);
            le16(&mut extra, (if big_size { 16 } else { 0 }) + if big_off { 8 } else { 0 });
            if big_size {
                le64(&mut extra, e.size);
                le64(&mut extra, e.size);
            }
            if big_off {
                le64(&mut extra, e.offset);
            }
        }
        le32(&mut cd, 0x02014b50);
        le16(&mut cd, (3 << 8) | 45);
        le16(&mut cd, if big_size || big_off { 45 } else { 20 });
        le16(&mut cd, 0x0800);
        le16(&mut cd, 0);
        le16(&mut cd, e.time);
        le16(&mut cd, e.date);
        le32(&mut cd, e.crc);
        le32(&mut cd, if big_size { FF } else { e.size as u32 });
        le32(&mut cd, if big_size { FF } else { e.size as u32 });
        le16(&mut cd, e.name.len() as u16);
        le16(&mut cd, extra.len() as u16);
        le16(&mut cd, 0);
        le16(&mut cd, 0);
        le16(&mut cd, 0);
        le32(&mut cd, 0o100644 << 16);
        le32(&mut cd, if big_off { FF } else { e.offset as u32 });
        cd.extend_from_slice(e.name.as_bytes());
        cd.extend_from_slice(&extra);
    }
    let cd_len = cd.len() as u64;
    let n = entries.len() as u64;
    let z64 = n >= 0xffff || cd_start >= FF as u64 || cd_len >= FF as u64;
    if z64 {
        let eocd64 = cd_start + cd_len;
        le32(&mut cd, 0x06064b50);
        le64(&mut cd, 44);
        le16(&mut cd, 45);
        le16(&mut cd, 45);
        le32(&mut cd, 0);
        le32(&mut cd, 0);
        le64(&mut cd, n);
        le64(&mut cd, n);
        le64(&mut cd, cd_len);
        le64(&mut cd, cd_start);
        le32(&mut cd, 0x07064b50);
        le32(&mut cd, 0);
        le64(&mut cd, eocd64);
        le32(&mut cd, 1);
    }
    le32(&mut cd, 0x06054b50);
    le16(&mut cd, 0);
    le16(&mut cd, 0);
    le16(&mut cd, if z64 { 0xffff } else { n as u16 });
    le16(&mut cd, if z64 { 0xffff } else { n as u16 });
    le32(&mut cd, if z64 { FF } else { cd_len as u32 });
    le32(&mut cd, if z64 { FF } else { cd_start as u32 });
    le16(&mut cd, 0);
    w.write_all(&cd)
}

pub fn download(run: &Arc<Run>) -> Response {
    let files: Vec<(String, std::path::PathBuf)> = list_files(&run.out_dir)
        .into_iter()
        .map(|(n, _)| (n.clone(), run.out_dir.join(&n)))
        .filter(|(_, p)| std::fs::symlink_metadata(p).map(|m| m.file_type().is_file()).unwrap_or(false))
        .collect();
    let short = run.plugin.name().rsplit('.').nth(1).unwrap_or("files");
    let name = format!("{short}-run{}-files.zip", run.id);
    Response::new(200)
        .header("content-disposition", format!("attachment; filename=\"{name}\""))
        .header("cache-control", "no-store")
        .stream("application/zip", Box::new(move |w: &mut dyn Write| write_zip(w, &files)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn zip_roundtrip_with_unzip() {
        let dir = std::env::temp_dir().join(format!("rsvol-zip-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        std::fs::write(dir.join("b.bin"), vec![7u8; 100_000]).unwrap();
        let files = vec![("a.txt".to_string(), dir.join("a.txt")), ("b.bin".to_string(), dir.join("b.bin"))];
        let mut out = Vec::new();
        super::write_zip(&mut out, &files).unwrap();
        let zp = dir.join("t.zip");
        std::fs::write(&zp, &out).unwrap();
        // validate with the system unzip when it is installed
        if let Ok(o) = std::process::Command::new("unzip").arg("-t").arg(&zp).output() {
            let s = String::from_utf8_lossy(&o.stdout);
            assert!(s.contains("No errors detected"), "{s}");
        }
        assert_eq!(&out[..4], b"PK\x03\x04");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
