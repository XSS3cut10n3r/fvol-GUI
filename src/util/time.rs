//! Time conversions matching volatility3 `framework/renderers/conversion.py` plus python
//! `datetime` / `time` formatting helpers.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! * [`wintime_to_datetime`] – FILETIME (100ns ticks since 1601) -> `Value::DateTime`,
//!   `Value::NotApplicable` for 0, `Value::Unparsable` when out of python's datetime range.
//! * [`unixtime_to_datetime`] – seconds since epoch -> `Value::DateTime` or `Value::Unparsable`
//!   (for `<= 0` or out of range), exactly as python.
//! * [`DateTime`] helpers: [`fmt_quick`] (renderer format), [`py_str`] (python `str(dt)`),
//!   [`asctime`] (python `time.asctime(time.gmtime(t))`).

use crate::renderers::{DateTime, Value};
use std::fmt::Write as _;

/// Smallest / largest unix timestamps python's `datetime` accepts (years 1..=9999).
pub const MIN_UNIX: i64 = -62_135_596_800;
pub const MAX_UNIX: i64 = 253_402_300_799;

/// Seconds between 1601-01-01 and 1970-01-01.
pub const EPOCH_DIFF_1601: i64 = 11_644_473_600;

/// python `conversion.wintime_to_datetime(wintime)`.
///
/// `wintime // 10_000_000` (floor division) seconds; 0 -> N/A; then `datetime.fromtimestamp`
/// which fails (-> Unparsable) outside years 1..9999. Microseconds are always 0 (python
/// discards the sub-second part).
pub fn wintime_to_datetime(wintime: i128) -> Value {
    let unix = wintime.div_euclid(10_000_000);
    if unix == 0 {
        return Value::NotApplicable;
    }
    let unix = unix - EPOCH_DIFF_1601 as i128;
    match unix_checked(unix) {
        Some(dt) => Value::DateTime(dt),
        None => Value::Unparsable,
    }
}

/// Like [`wintime_to_datetime`] but returns `Some(DateTime)` only for a real datetime.
pub fn wintime_to_dt(wintime: i128) -> Option<DateTime> {
    match wintime_to_datetime(wintime) {
        Value::DateTime(d) => Some(d),
        _ => None,
    }
}

/// python `conversion.unixtime_to_datetime(unixtime)`: `> 0` and in range, else Unparsable.
pub fn unixtime_to_datetime(unixtime: i128) -> Value {
    if unixtime > 0 {
        if let Some(dt) = unix_checked(unixtime) {
            return Value::DateTime(dt);
        }
    }
    Value::Unparsable
}

/// python `datetime.datetime.fromtimestamp(t, timezone.utc)` for a float timestamp (rounded to
/// microseconds with round-half-even like python). None when out of range.
pub fn unix_float_to_dt(t: f64) -> Option<DateTime> {
    if !t.is_finite() {
        return None;
    }
    let secs = t.floor();
    let frac = t - secs;
    // python rounds to the nearest microsecond using round-half-even
    let us = (frac * 1e6).round_ties_even();
    let (mut s, mut us) = (secs as i64, us as i64);
    if us >= 1_000_000 {
        s += 1;
        us -= 1_000_000;
    }
    if !(MIN_UNIX..=MAX_UNIX).contains(&s) {
        return None;
    }
    Some(DateTime { secs: s, micros: us as u32, utc: true })
}

/// A UTC datetime for `secs` if python can represent it (years 1..=9999).
pub fn unix_checked(secs: i128) -> Option<DateTime> {
    if secs < MIN_UNIX as i128 || secs > MAX_UNIX as i128 {
        return None;
    }
    Some(DateTime { secs: secs as i64, micros: 0, utc: true })
}

/// Broken-down civil time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// 0 = Monday .. 6 = Sunday (python `weekday()`)
    pub weekday: u32,
    /// 1..=366
    pub yday: u32,
}

/// Days since 1970-01-01 -> (year, month, day). (Howard Hinnant's algorithm.)
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) -> days since 1970-01-01.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Break down unix seconds (UTC).
pub fn civil(secs: i64) -> Civil {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday (weekday 3)
    let weekday = (days + 3).rem_euclid(7) as u32;
    let yday = (days - days_from_civil(year, 1, 1) + 1) as u32;
    Civil {
        year,
        month,
        day,
        hour: (rem / 3600) as u32,
        minute: ((rem % 3600) / 60) as u32,
        second: (rem % 60) as u32,
        weekday,
        yday,
    }
}

const WDAY: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// The quick/pretty renderer format: `strftime("%Y-%m-%d %H:%M:%S.%f %Z")`
/// (`%Z` is "UTC" for aware datetimes and empty for naive ones).
pub fn fmt_quick(dt: &DateTime) -> String {
    let c = civil(dt.secs);
    let mut s = String::with_capacity(32);
    let _ = write!(
        s,
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06} {}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        dt.micros,
        if dt.utc { "UTC" } else { "" }
    );
    s
}

/// python `str(datetime)` / `datetime.isoformat(sep=" ")`:
/// `YYYY-MM-DD HH:MM:SS[.ffffff][+00:00]`.
pub fn py_str(dt: &DateTime) -> String {
    py_isoformat(dt, ' ')
}

/// python `datetime.isoformat(sep)`.
pub fn py_isoformat(dt: &DateTime, sep: char) -> String {
    let c = civil(dt.secs);
    let mut s = String::with_capacity(32);
    let _ = write!(s, "{:04}-{:02}-{:02}{}{:02}:{:02}:{:02}", c.year, c.month, c.day, sep, c.hour, c.minute, c.second);
    if dt.micros != 0 {
        let _ = write!(s, ".{:06}", dt.micros);
    }
    if dt.utc {
        s.push_str("+00:00");
    }
    s
}

/// python `time.asctime(time.gmtime(t))`, e.g. `"Sun Feb 19 04:00:02 1984"`.
pub fn asctime(secs: i64) -> String {
    let c = civil(secs);
    format!(
        "{} {}{:3} {:02}:{:02}:{:02} {}",
        WDAY[c.weekday as usize],
        MON[(c.month - 1) as usize],
        c.day,
        c.hour,
        c.minute,
        c.second,
        c.year
    )
}

/// Year of a datetime (for plausibility checks like `1998 < ctime.year < now + 10`).
pub fn year(dt: &DateTime) -> i64 {
    civil(dt.secs).year
}

/// Current UTC year (python `datetime.datetime.now().year`, local time in python; UTC here is
/// close enough for the "+10 years" sanity checks it is used for).
pub fn current_year() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    civil(now).year
}

/// Days in a month.
pub fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wintime() {
        // 2026-09-14 02:53:44 UTC
        let secs = days_from_civil(2026, 9, 14) * 86400 + 2 * 3600 + 53 * 60 + 44;
        let wt = (secs as i128 + EPOCH_DIFF_1601 as i128) * 10_000_000 + 1234;
        match wintime_to_datetime(wt) {
            Value::DateTime(d) => assert_eq!(fmt_quick(&d), "2026-09-14 02:53:44.000000 UTC"),
            v => panic!("{v:?}"),
        }
        assert!(matches!(wintime_to_datetime(0), Value::NotApplicable));
        assert!(matches!(wintime_to_datetime(9_999_999), Value::NotApplicable));
        assert!(matches!(wintime_to_datetime(-1), Value::Unparsable) || matches!(wintime_to_datetime(-1), Value::DateTime(_)));
        assert!(matches!(wintime_to_datetime(i64::MAX as i128), Value::Unparsable));
        assert!(matches!(unixtime_to_datetime(0), Value::Unparsable));
    }
    #[test]
    fn formats() {
        assert_eq!(asctime(0), "Thu Jan  1 00:00:00 1970");
        assert_eq!(asctime(3 * 86400), "Sun Jan  4 00:00:00 1970");
        let d = DateTime { secs: 441_000_002, micros: 0, utc: true };
        assert_eq!(asctime(441_000_002), "Fri Dec 23 04:00:02 1983");
        assert_eq!(py_str(&d), "1983-12-23 04:00:02+00:00");
        let d = DateTime { secs: MIN_UNIX, micros: 5, utc: true };
        assert_eq!(py_str(&d), "0001-01-01 00:00:00.000005+00:00");
        assert_eq!(civil(MAX_UNIX).year, 9999);
    }
}
