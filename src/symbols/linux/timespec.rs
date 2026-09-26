//! python `Timespec64Abstract` / `Timespec64Concrete` (symbols/linux/extensions) with python's
//! exact numeric semantics: `linux_constants.NSEC_PER_SEC` is the FLOAT `1e9`, so most values
//! become floats (`nsec // 1e9`, `nsec % 1e9`, ...) and the datetime/timedelta conversions
//! round like CPython. Output (creation times with microseconds) depends on every rounding step.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::renderers::DateTime;
use crate::util::time::{MAX_UNIX, MIN_UNIX, unix_float_to_dt};
use std::cmp::Ordering;

/// python `linux_constants.NSEC_PER_SEC` (a float).
pub const NSEC_PER_SEC: f64 = 1e9;

/// A python number: `int` or `float`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PyNum {
    I(i128),
    F(f64),
}

/// CPython `_float_div_mod(vx, wx)`: (floor quotient, modulo) for floats.
pub fn float_divmod(vx: f64, wx: f64) -> (f64, f64) {
    let mut m = vx % wx;
    let mut div = (vx - m) / wx;
    if m != 0.0 {
        if (wx < 0.0) != (m < 0.0) {
            m += wx;
            div -= 1.0;
        }
    } else {
        m = 0f64.copysign(wx);
    }
    let floordiv = if div != 0.0 {
        let mut f = div.floor();
        if div - f > 0.5 {
            f += 1.0;
        }
        f
    } else {
        0f64.copysign(vx / wx)
    };
    (floordiv, m)
}

/// CPython `float_rem`.
pub fn float_rem(vx: f64, wx: f64) -> f64 {
    let mut m = vx % wx;
    if m != 0.0 {
        if (wx < 0.0) != (m < 0.0) {
            m += wx;
        }
    } else {
        m = 0f64.copysign(wx);
    }
    m
}

impl PyNum {
    /// python `float(x)` (ints round to nearest-even like `PyLong_AsDouble`).
    #[inline]
    pub fn f(self) -> f64 {
        match self {
            PyNum::I(i) => i as f64,
            PyNum::F(f) => f,
        }
    }
    pub fn add(self, o: PyNum) -> PyNum {
        match (self, o) {
            (PyNum::I(a), PyNum::I(b)) => PyNum::I(a.saturating_add(b)),
            _ => PyNum::F(self.f() + o.f()),
        }
    }
    pub fn sub(self, o: PyNum) -> PyNum {
        self.add(o.neg())
    }
    pub fn neg(self) -> PyNum {
        match self {
            PyNum::I(a) => PyNum::I(a.saturating_neg()),
            PyNum::F(f) => PyNum::F(-f),
        }
    }
    /// python `a // b` with `b` a float.
    pub fn floordiv_f(self, b: f64) -> PyNum {
        PyNum::F(float_divmod(self.f(), b).0)
    }
    /// python `a % b` with `b` a float.
    pub fn rem_f(self, b: f64) -> PyNum {
        PyNum::F(float_rem(self.f(), b))
    }
    /// python comparison (exact between ints and floats, like CPython).
    pub fn cmp(self, o: PyNum) -> Option<Ordering> {
        match (self, o) {
            (PyNum::I(a), PyNum::I(b)) => Some(a.cmp(&b)),
            (PyNum::F(a), PyNum::F(b)) => a.partial_cmp(&b),
            (PyNum::I(a), PyNum::F(b)) => cmp_int_float(a, b),
            (PyNum::F(a), PyNum::I(b)) => cmp_int_float(b, a).map(|o| o.reverse()),
        }
    }
    fn lt(self, o: PyNum) -> bool {
        self.cmp(o) == Some(Ordering::Less)
    }
    fn ge(self, o: PyNum) -> bool {
        matches!(self.cmp(o), Some(Ordering::Greater | Ordering::Equal))
    }
}

fn cmp_int_float(i: i128, f: f64) -> Option<Ordering> {
    if f.is_nan() {
        return None;
    }
    if f >= 1e38 {
        return Some(Ordering::Less);
    }
    if f <= -1e38 {
        return Some(Ordering::Greater);
    }
    let fl = f.floor();
    let fi = fl as i128;
    Some(match i.cmp(&fi) {
        Ordering::Equal => {
            if fl == f {
                Ordering::Equal
            } else {
                Ordering::Less
            }
        }
        o => o,
    })
}

/// python `Timespec64Concrete`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Timespec {
    pub tv_sec: PyNum,
    pub tv_nsec: PyNum,
}

const NSEC: PyNum = PyNum::F(NSEC_PER_SEC);

impl Timespec {
    /// python `new_from_timespec(other)`: `int(other.tv_sec)`, `int(other.tv_nsec)`.
    pub fn from_ints(tv_sec: i128, tv_nsec: i128) -> Timespec {
        Timespec { tv_sec: PyNum::I(tv_sec), tv_nsec: PyNum::I(tv_nsec) }
    }

    /// python `new_from_nsec(nsec)` (based on the kernel's `ns_to_timespec64`).
    pub fn from_nsec(nsec: PyNum) -> Timespec {
        let zero = PyNum::I(0);
        if nsec.cmp(zero) == Some(Ordering::Greater) {
            Timespec { tv_sec: nsec.floordiv_f(NSEC_PER_SEC), tv_nsec: nsec.rem_f(NSEC_PER_SEC) }
        } else if nsec.lt(zero) {
            let m = nsec.neg().sub(PyNum::I(1));
            let tv_sec = m.floordiv_f(NSEC_PER_SEC).neg().sub(PyNum::I(1));
            let rem = m.rem_f(NSEC_PER_SEC);
            Timespec { tv_sec, tv_nsec: NSEC.sub(rem).sub(PyNum::I(1)) }
        } else {
            Timespec::from_ints(0, 0)
        }
    }

    /// python `normalize()` (the kernel's `set_normalized_timespec64`). python loops one
    /// second at a time; exact closed forms are used where the loop would be long.
    pub fn normalize(&mut self) {
        let mut guard = 0u32;
        while self.tv_nsec.ge(NSEC) {
            if guard > 64 {
                if let Some(k) = whole_seconds(self.tv_nsec) {
                    self.tv_nsec = sub_many(self.tv_nsec, k);
                    self.tv_sec = self.tv_sec.add(PyNum::I(k));
                    guard = 0;
                    continue;
                }
                return;
            }
            self.tv_nsec = self.tv_nsec.sub(NSEC);
            self.tv_sec = self.tv_sec.add(PyNum::I(1));
            guard += 1;
        }
        let mut guard = 0u32;
        while self.tv_nsec.lt(PyNum::I(0)) {
            if guard > 64 {
                if let Some(k) = whole_seconds(self.tv_nsec.neg()) {
                    let k = k.max(1);
                    self.tv_nsec = sub_many(self.tv_nsec, -k);
                    self.tv_sec = self.tv_sec.sub(PyNum::I(k));
                    guard = 0;
                    continue;
                }
                return;
            }
            self.tv_nsec = self.tv_nsec.add(NSEC);
            self.tv_sec = self.tv_sec.sub(PyNum::I(1));
            guard += 1;
        }
    }

    /// python `__add__`.
    pub fn add(&self, o: &Timespec) -> Timespec {
        let mut r = Timespec { tv_sec: self.tv_sec.add(o.tv_sec), tv_nsec: self.tv_nsec.add(o.tv_nsec) };
        r.normalize();
        r
    }

    /// python `__sub__`.
    pub fn sub(&self, o: &Timespec) -> Timespec {
        self.add(&o.negate())
    }

    /// python `negate()`.
    pub fn negate(&self) -> Timespec {
        let mut r = Timespec { tv_sec: self.tv_sec.neg(), tv_nsec: self.tv_nsec.neg() };
        r.normalize();
        r
    }

    /// `tv_sec + tv_nsec / NSEC_PER_SEC` (always a float).
    pub fn seconds(&self) -> f64 {
        self.tv_sec.add(PyNum::F(self.tv_nsec.f() / NSEC_PER_SEC)).f()
    }

    /// python `to_datetime()` = `conversion.unixtime_to_datetime(seconds)`: `None` where python
    /// returns an `UnparsableValue` (`<= 0` or out of range).
    pub fn to_datetime(&self) -> Option<DateTime> {
        let t = self.seconds();
        if t > 0.0 { unix_float_to_dt(t) } else { None }
    }

    /// python `to_timedelta()` as microseconds (`Err` where python raises).
    pub fn to_timedelta_us(&self) -> Result<i128> {
        timedelta_seconds_us(self.seconds())
    }
}

/// For an integral float/int `v >= 1e9`: the number of whole seconds python's loop would
/// subtract, when that can be computed exactly.
fn whole_seconds(v: PyNum) -> Option<i128> {
    match v {
        PyNum::I(i) => Some(i.div_euclid(1_000_000_000)),
        PyNum::F(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.0e15 => Some((f as i128).div_euclid(1_000_000_000)),
        _ => None,
    }
}

/// `v - k * 1e9` computed exactly (python's repeated float subtraction is exact in this range).
fn sub_many(v: PyNum, k: i128) -> PyNum {
    match v {
        PyNum::I(i) => PyNum::F((i - k * 1_000_000_000) as f64),
        PyNum::F(f) => PyNum::F(((f as i128) - k * 1_000_000_000) as f64),
    }
}

/// CPython `datetime.timedelta(seconds=s)` for a float `s`, as total microseconds (exactly
/// like `delta_new`'s `accum` + round-half-even of the leftover). `Err` = OverflowError /
/// ValueError.
pub fn timedelta_seconds_us(s: f64) -> Result<i128> {
    if !s.is_finite() {
        return Err(Error::msg("cannot convert float to integer"));
    }
    let int_part = s.trunc();
    let frac = s - int_part;
    let mut x: i128 = (int_part as i128).checked_mul(1_000_000).ok_or_else(|| Error::msg("OverflowError"))?;
    let mut leftover = 0.0f64;
    if frac != 0.0 {
        let dnum = 1e6 * frac;
        let ip = dnum.trunc();
        x += ip as i128;
        leftover = dnum - ip;
    }
    if leftover != 0.0 {
        let mut whole = leftover.round();
        if (whole - leftover).abs() == 0.5 {
            let odd = (x & 1) as f64;
            whole = 2.0 * ((leftover + odd) * 0.5).round() - odd;
        }
        x += whole as i128;
    }
    // python: |days| <= 999999999
    let days = x.div_euclid(86_400_000_000);
    if days.abs() > 999_999_999 {
        return Err(Error::msg("OverflowError: days out of range"));
    }
    Ok(x)
}

/// python `datetime + timedelta(microseconds=us)` (`Err` = OverflowError).
pub fn datetime_add_us(dt: DateTime, us: i128) -> Result<DateTime> {
    let total = dt.secs as i128 * 1_000_000 + dt.micros as i128 + us;
    let secs = total.div_euclid(1_000_000);
    let micros = total.rem_euclid(1_000_000) as u32;
    if secs < MIN_UNIX as i128 || secs > MAX_UNIX as i128 {
        return Err(Error::msg("OverflowError: date value out of range"));
    }
    Ok(DateTime { secs: secs as i64, micros, utc: dt.utc })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_float_divmod() {
        assert_eq!(float_divmod(7.0, 2.0), (3.0, 1.0));
        assert_eq!(float_divmod(-7.0, 2.0), (-4.0, 1.0));
        assert_eq!(float_rem(-7.0, 2.0), 1.0);
        // big int -> float then // 1e9 (python: 1790000000123456789 // 1e9 == 1790000000.0)
        let t = Timespec::from_nsec(PyNum::I(1_790_000_000_123_456_789));
        assert_eq!(t.tv_sec, PyNum::F(1790000000.0));
        assert_eq!(t.tv_nsec, PyNum::F(123456768.0));
        let n = Timespec::from_nsec(PyNum::I(-1_500_000_000));
        assert_eq!(n.tv_sec, PyNum::F(-2.0));
        assert_eq!(n.tv_nsec, PyNum::F(500000000.0));
    }

    #[test]
    fn timedelta_rounding() {
        // timedelta(seconds=0.0000005) -> 0 us (half-even of 0.5 with x even)
        assert_eq!(timedelta_seconds_us(0.0000005).unwrap(), 0);
        assert_eq!(timedelta_seconds_us(1.5).unwrap(), 1_500_000);
        assert_eq!(timedelta_seconds_us(2.0000015).unwrap(), 2_000_002);
    }

    #[test]
    fn normalize_like_python() {
        let mut t = Timespec { tv_sec: PyNum::I(5), tv_nsec: PyNum::I(-1) };
        t.normalize();
        assert_eq!(t.tv_sec, PyNum::I(4));
        assert_eq!(t.tv_nsec, PyNum::F(999999999.0));
    }
}
