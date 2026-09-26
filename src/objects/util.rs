//! python `framework/objects/utility.py`: string helpers and bit tricks.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use super::strings::{bytes_to_decoded_string, parse_encoding, parse_errors};
use super::{LayerRef, Obj};
use crate::error::{Error, Result};
use crate::layers::Layer;
use crate::symbols::Ty;

/// python `utility.rol(value, count, max_bits=64)`.
pub fn rol(value: u64, count: u32, max_bits: u32) -> u64 {
    let mask = if max_bits >= 64 { u64::MAX } else { (1u64 << max_bits) - 1 };
    let c = count % max_bits;
    if c == 0 {
        return value & mask;
    }
    ((value << c) & mask) | ((value & mask) >> (max_bits - c))
}

/// python `utility.bswap_32`.
pub fn bswap_32(v: u64) -> u64 {
    (v as u32).swap_bytes() as u64
}

/// python `utility.bswap_64`.
pub fn bswap_64(v: u64) -> u64 {
    v.swap_bytes()
}

/// python `gather_contiguous_bytes_from_address`: read up to `count` bytes, stopping at the first
/// unmapped page (error if nothing could be read).
pub fn gather_contiguous_bytes(layer: &dyn Layer, start: u64, count: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    if layer.lower().is_some() {
        let mut last = start;
        let mut runs = Vec::new();
        layer.mapping(start, count, &mut |m| {
            if m.offset != last {
                return false;
            }
            last = m.offset + m.len;
            runs.push((m.offset, m.len));
            true
        });
        for (off, len) in runs {
            let mut b = vec![0u8; len as usize];
            layer.read(off, &mut b)?;
            data.extend_from_slice(&b);
        }
    } else if start.saturating_add(count) < layer.max_address() {
        let mut b = vec![0u8; count as usize];
        layer.read(start, &mut b)?;
        data = b;
    }
    if data.is_empty() { Err(Error::invalid(start)) } else { Ok(data) }
}

/// python `utility.address_to_string(context, layer, address, count, errors, encoding)`.
pub fn address_to_string(layer: LayerRef, address: u64, count: u64, errors: &str, encoding: &str) -> Result<String> {
    if count < 1 {
        return Err(Error::msg("Count must be greater than 0"));
    }
    let data = gather_contiguous_bytes(layer, address, count)?;
    bytes_to_decoded_string(&data, parse_encoding(encoding), parse_errors(errors))
}

/// python `utility.array_to_string(array, count=None, errors="replace")`.
pub fn array_to_string(array: &Obj, count: Option<u64>) -> Result<String> {
    array_to_string_ex(array, count, "replace", "utf-8")
}

/// python `utility.array_to_string(array, count, errors, encoding=...)`.
pub fn array_to_string_ex(array: &Obj, count: Option<u64>, errors: &str, encoding: &str) -> Result<String> {
    if !array.is_array() {
        return Err(Error::msg("Array_to_string takes an Array of char"));
    }
    let count = count.unwrap_or(array.count());
    address_to_string(array.layer(), array.addr, count, errors, encoding)
}

/// python `utility.pointer_to_string(pointer, count, errors="replace")`.
pub fn pointer_to_string(pointer: &Obj, count: u64) -> Result<String> {
    pointer_to_string_ex(pointer, count, "replace", "utf-8")
}

/// python `utility.pointer_to_string(pointer, count, errors, encoding)`.
pub fn pointer_to_string_ex(pointer: &Obj, count: u64, errors: &str, encoding: &str) -> Result<String> {
    if !pointer.is_pointer() {
        return Err(Error::msg("pointer_to_string takes a Pointer"));
    }
    if count < 1 {
        return Err(Error::msg("pointer_to_string requires a positive count"));
    }
    let addr = pointer.u64()?;
    address_to_string(pointer.layer(), addr, count, errors, encoding)
}

/// python `utility.array_of_pointers(array, count, subtype)`: recast as `count` pointers to
/// `subtype`.
pub fn array_of_pointers(array: &Obj, count: u64, subtype: Ty) -> Result<Obj> {
    let ptr = array.cast_pointer_to(subtype)?;
    Ok(array.cast_array(count, ptr.ty))
}
