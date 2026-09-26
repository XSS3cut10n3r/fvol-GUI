// Derived from Volatility 3 (Volatility Software License 1.0):
// framework/symbols/windows/pdbconv.py, pdbutil.py, framework/layers/msf.py
//! Windows PDB support: PDB -> ISF conversion, symbol-server download, PE CodeView (RSDS)
//! extraction and the `PdbSignatureScanner` matcher.
//!
//! Public API:
//!   * [`pdb_to_isf_json`] / [`pdb_to_isf_json_named`] — python `PdbReader(...).get_json()`
//!     followed by `json.dumps(indent=2, sort_keys=True)`, byte-identical except for the
//!     producer datetime;
//!   * [`fetch_pdb`] / [`download_pdb`] / [`download_and_convert`] — python `PdbRetreiver` /
//!     `PDBUtility.download_pdb_isf` (curl is used for HTTPS);
//!   * [`pe_codeview_info`] — python `PDBUtility.get_guid_from_mz` over raw image bytes;
//!   * [`rsds_scan`], [`find_mz_before`], [`PdbNameScan`] — `PdbSignatureScanner` and the
//!     MZ back-search of `PDBUtility.pdbname_scan`.

mod download;
mod json;
mod msf;
mod pe;
mod reader;
mod scan;

pub use download::{
    download_and_convert, download_pdb, fetch_pdb, isf_relative_path, pdb_cache_path, set_python_cache, symbol_server_urls, SYMBOL_SERVER_URL,
};
pub use pe::{find_mz_before, find_rsds, guid_string, pe_codeview_info, pe_image_size, rsds_scan, rsds_search, CodeViewInfo, PdbNameScan, PdbScanResult, RsdsMatch};

use crate::error::{Error, Result};

/// Internal error: python's `ValueError` must be distinguishable because `read_ipi_stream`
/// swallows it.
#[derive(Debug)]
pub(crate) enum PErr {
    /// python `ValueError`
    Value(String),
    /// python `InvalidAddressException` (read outside the stream / file)
    Invalid(u64),
    /// anything else python raises (TypeError, KeyError, IndexError, ...)
    Other(String),
}

pub(crate) type PResult<T> = std::result::Result<T, PErr>;

impl From<PErr> for Error {
    fn from(e: PErr) -> Error {
        match e {
            PErr::Value(m) => Error::Symbol(format!("PDB conversion failed: ValueError: {m}")),
            PErr::Invalid(a) => Error::Symbol(format!("PDB conversion failed: invalid address {a:#x}")),
            PErr::Other(m) => Error::Symbol(format!("PDB conversion failed: {m}")),
        }
    }
}

/// `constants.PACKAGE_VERSION` written into `metadata.producer.version`.
pub fn producer_version() -> &'static str {
    crate::VERSION_BANNER.rsplit(' ').next().unwrap_or("2.28.2")
}

/// Converts a PDB file to ISF JSON text exactly like `pdbconv.py -f FILE` does (the
/// `metadata.windows.pdb.database` name is taken from the IPI stream, or "unknown.pdb").
pub fn pdb_to_isf_json(pdb: &[u8]) -> Result<String> {
    pdb_to_isf_json_named(pdb, None)
}

/// Converts a PDB file to ISF JSON text; `database_name` is what volatility3 passes as
/// `PdbReader(..., database_name)` (the PDB file name when downloading via `pdbutil`,
/// `None` for `pdbconv.py -f`).
pub fn pdb_to_isf_json_named(pdb: &[u8], database_name: Option<&str>) -> Result<String> {
    let bytes = pdb_to_isf_bytes(pdb, database_name, &python_now_isoformat())?;
    // The writer only emits ASCII (ensure_ascii escaping).
    String::from_utf8(bytes).map_err(|_| Error::msg("PDB conversion produced non-ASCII output"))
}

/// Like [`pdb_to_isf_json_named`] with an explicit producer datetime, returning raw bytes.
pub fn pdb_to_isf_bytes(pdb: &[u8], database_name: Option<&str>, datetime: &str) -> Result<Vec<u8>> {
    let db = match database_name {
        Some(n) => reader::DbName::Given(n),
        None => reader::DbName::FromIpi,
    };
    Ok(reader::convert(pdb, db, datetime, producer_version())?)
}

/// `datetime.datetime.now().isoformat()` (local time, microseconds omitted when zero).
pub fn python_now_isoformat() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let micros = now.subsec_micros();
    let (y, mo, d, h, mi, s) = local_time(secs);
    let mut out = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}");
    if micros != 0 {
        out.push_str(&format!(".{micros:06}"));
    }
    out
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn local_time(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    #[repr(C)]
    struct Tm {
        sec: i32,
        min: i32,
        hour: i32,
        mday: i32,
        mon: i32,
        year: i32,
        wday: i32,
        yday: i32,
        isdst: i32,
        gmtoff: i64,
        zone: *const u8,
    }
    unsafe extern "C" {
        fn tzset();
        fn localtime_r(t: *const i64, tm: *mut Tm) -> *mut Tm;
    }
    let mut tm = Tm {
        sec: 0,
        min: 0,
        hour: 0,
        mday: 1,
        mon: 0,
        year: 70,
        wday: 0,
        yday: 0,
        isdst: 0,
        gmtoff: 0,
        zone: std::ptr::null(),
    };
    // SAFETY: plain libc calls with valid pointers to stack values.
    let ok = unsafe {
        tzset();
        !localtime_r(&secs, &mut tm).is_null()
    };
    if !ok {
        return utc_time(secs);
    }
    (tm.year as i64 + 1900, tm.mon as u32 + 1, tm.mday as u32, tm.hour as u32, tm.min as u32, tm.sec as u32)
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn local_time(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    utc_time(secs)
}

/// Civil-from-days (proleptic Gregorian) UTC conversion.
fn utc_time(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + (m <= 2) as i64;
    (y, m, d, (rem / 3600) as u32, (rem % 3600 / 60) as u32, (rem % 60) as u32)
}

#[cfg(test)]
mod tests;
