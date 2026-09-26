//! linux.graphics.fbdev.Fbdev (python `plugins/linux/graphics/fbdev.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! `--dump` writes each framebuffer as a PNG (python converts it with pillow when the pixel
//! format is RGB-like) or as the raw buffer (FOURCC formats).

use crate::context::Context;
use crate::error::Result;
use crate::layers::LayerExt;
use crate::objects::Obj;
use crate::objects::util::{array_of_pointers, array_to_string, pointer_to_string};
use crate::plugins::{Config, Plugin, Requirement};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::linux::utilities::convert_fourcc_code;

pub struct Fbdev;

/// python `Framebuffer`.
pub struct Framebuffer {
    /// `None` = python's NotAvailableValue (empty `fix.id`)
    pub id: Option<String>,
    pub xres_virtual: u64,
    pub yres_virtual: u64,
    pub line_length: u64,
    /// bits per pixel
    pub bpp: u64,
    pub size: u64,
    /// `R`, `G`, `B`, `A` -> (offset, length, msb_right); `None` for FOURCC formats
    pub color_fields: Option<[(u32, u32, u32); 4]>,
    /// the `fb_info *` pointer object
    pub fb_info: Obj,
}

/// python `Fbdev.parse_fb_pixel_bitfields(fb_var_screeninfo)`.
pub fn parse_fb_pixel_bitfields(var: &Obj) -> Result<[(u32, u32, u32); 4]> {
    let mut out = [(0, 0, 0); 4];
    for (i, m) in ["red", "green", "blue", "transp"].iter().enumerate() {
        let bf = var.m(m)?;
        out[i] = (bf.m("offset")?.int()? as u32, bf.m("length")?.int()? as u32, bf.m("msb_right")?.int()? as u32);
    }
    Ok(out)
}

/// python `Fbdev.parse_fb_info(fb_info)`.
pub fn parse_fb_info(fb_info: &Obj) -> Result<Framebuffer> {
    let id = array_to_string(&fb_info.m("fix")?.m("id")?, None)?;
    let id = if id.is_empty() { None } else { Some(id) };
    let var = fb_info.m("var")?;
    let grayscale = var.m("grayscale")?.int()?;
    let mut color_fields = None;
    if grayscale == 0 || grayscale == 1 {
        color_fields = Some(parse_fb_pixel_bitfields(&var)?);
    } else if grayscale > 1 {
        // python logs a warning naming the FOURCC pixel format
        let _fourcc = convert_fourcc_code(grayscale as u128);
    }
    let xres_virtual = var.m("xres_virtual")?.int()? as u64;
    let yres_virtual = var.m("yres_virtual")?.int()? as u64;
    let line_length = fb_info.m("fix")?.m("line_length")?.int()? as u64;
    let bpp = var.m("bits_per_pixel")?.int()? as u64;
    let size = (var.m("yres_virtual")?.int()? as u64).saturating_mul(fb_info.m("fix")?.m("line_length")?.int()? as u64);
    Ok(Framebuffer { id, xres_virtual, yres_virtual, line_length, bpp, size, color_fields, fb_info: *fb_info })
}

/// python `Fbdev.convert_fb_raw_buffer_to_image`: RGBA pixels (row-major, `xres * yres * 4`),
/// reading `bpp / 8` bytes per pixel sequentially from `raw` (short reads give 0 like
/// `int.from_bytes(b"")`), values clipped to 0..=255 like pillow's `putpixel`.
pub fn fb_raw_to_rgba(fb: &Framebuffer, raw: &[u8], fields: &[(u32, u32, u32); 4]) -> Vec<u8> {
    let bpp = (fb.bpp / 8) as usize;
    let n = (fb.xres_virtual * fb.yres_virtual) as usize;
    let mut out = Vec::with_capacity(n * 4);
    let mut pos = 0usize;
    for _ in 0..n {
        let end = (pos + bpp).min(raw.len());
        let mut raw_pixel: u128 = 0;
        if pos < end {
            for (i, &b) in raw[pos..end].iter().enumerate().take(16) {
                raw_pixel |= (b as u128) << (8 * i);
            }
        }
        pos = pos.saturating_add(bpp).min(raw.len().max(pos));
        let mut pixel = [0u64, 0, 0, 255];
        for (i, &(offset, length, msb_right)) in fields.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let mask: u128 = if length >= 128 { u128::MAX } else { (1u128 << length) - 1 };
            let mut v = if offset >= 128 { 0 } else { (raw_pixel >> offset) & mask };
            if msb_right != 0 {
                // int(f"{v:0{length}b}"[::-1], 2)
                let bits = format!("{v:0width$b}", width = length as usize);
                v = u128::from_str_radix(&bits.chars().rev().collect::<String>(), 2).unwrap_or(0);
            }
            pixel[i] = v.min(255) as u64;
        }
        out.extend(pixel.iter().map(|&c| c as u8));
    }
    out
}

/// A plain RGBA PNG (8-bit, colour type 6, one IDAT).
// TODO(l3): pillow-exact encoder from the codecs package
fn png_rgba(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, ty: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let start = out.len();
        out.extend_from_slice(ty);
        out.extend_from_slice(data);
        let crc = crate::codecs::crc::crc32(&out[start..]);
        out.extend_from_slice(&crc.to_be_bytes());
    }
    let mut raw = Vec::with_capacity(rgba.len() + height as usize);
    let stride = width as usize * 4;
    for row in 0..height as usize {
        raw.push(0);
        raw.extend_from_slice(&rgba[row * stride..(row + 1) * stride]);
    }
    // zlib stream with stored blocks
    let mut z = vec![0x78, 0x01];
    let chunks: Vec<&[u8]> = raw.chunks(65535).collect();
    if chunks.is_empty() {
        z.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    for (i, c) in chunks.iter().enumerate() {
        z.push((i + 1 == chunks.len()) as u8);
        z.extend_from_slice(&(c.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        z.extend_from_slice(c);
    }
    z.extend_from_slice(&crate::codecs::zlib::adler32(&raw).to_be_bytes());
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}

/// python `Fbdev.dump_fb(context, kernel, open_method, fb, convert_to_png_image)`: the file
/// name python returns (the requested name). `Err` where python raises (the kernel layer read
/// raises InvalidAddressException before any file is created).
pub fn dump_fb(ctx: &Context, fb: &Framebuffer, convert_to_png: bool) -> Result<String> {
    let k = ctx.linux_kernel()?;
    let id = fb.id.as_deref().unwrap_or("N-A");
    let base = format!("{id}_{}x{}_{}bpp", fb.xres_virtual, fb.yres_virtual, fb.bpp);
    let screen_base = fb.fb_info.m("screen_base")?.u64()?;
    // a smeared size must not make us allocate absurd buffers: python's strict read raises
    // InvalidAddressException on the first unmapped page anyway
    if fb.size > 1 << 28 && !k.vlayer.is_valid(screen_base, fb.size) {
        return Err(crate::error::Error::invalid(screen_base));
    }
    let data = k.vlayer.read_vec(screen_base, fb.size as usize)?;
    let (buf, filename) = match (&fb.color_fields, convert_to_png) {
        (Some(fields), true) => {
            let rgba = fb_raw_to_rgba(fb, &data, fields);
            (png_rgba(fb.xres_virtual as u32, fb.yres_virtual as u32, &rgba), format!("{base}.png"))
        }
        _ => (data, format!("{base}.raw")),
    };
    use std::io::Write;
    let (mut f, _final) = ctx.create_output_file(&filename)?;
    f.write_all(&buf)?;
    Ok(filename)
}

impl Plugin for Fbdev {
    fn name(&self) -> &'static str {
        "linux.graphics.fbdev.Fbdev"
    }
    fn description(&self) -> &'static str {
        "Extract framebuffers from the fbdev graphics subsystem"
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::flag("dump", "Dump framebuffers")]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        out.begin(vec![
            Column::new("Address", ColType::Hex),
            Column::new("Device", ColType::Str),
            Column::new("ID", ColType::Str),
            Column::new("Size", ColType::Int),
            Column::new("Virtual resolution", ColType::Str),
            Column::new("BPP", ColType::Int),
            Column::new("State", ColType::Str),
            Column::new("Filename", ColType::Str),
        ])?;
        let k = ctx.linux_kernel()?;
        if !k.has_symbol("num_registered_fb") {
            return Ok(());
        }
        let num_registered_fb = match k.object_from_symbol("num_registered_fb") {
            Ok(o) => o.int()?,
            Err(crate::error::Error::Symbol(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        if num_registered_fb < 1 {
            return Ok(());
        }
        let registered_fb = k.object_from_symbol("registered_fb")?;
        let fb_info_ty = k.get_type("fb_info")?;
        let list = array_of_pointers(&registered_fb, num_registered_fb as u64, fb_info_ty)?;
        let dump = cfg.get_bool("dump");
        for i in 0..list.count() {
            let fb_info = list.at(i)?;
            let fb = parse_fb_info(&fb_info)?;
            let mut file_output = Value::SStr("Disabled");
            if dump {
                file_output = match dump_fb(ctx, &fb, fb.color_fields.is_some()) {
                    Ok(name) => Value::Str(name),
                    Err(e) if e.is_invalid_address() => Value::Unreadable,
                    Err(e) => return Err(e),
                };
            }
            let device = match fb_info.m("dev").and_then(|d| d.m("kobj")).and_then(|k| k.m("name")).and_then(|n| pointer_to_string(&n, 256)) {
                Ok(s) => Value::Str(s),
                Err(e) if e.is_invalid_address() => Value::NotAvailable,
                Err(e) => return Err(e),
            };
            let state = fb_info.m("state")?.int()?;
            out.row(
                0,
                vec![
                    Value::Int(fb_info.m("screen_base")?.u64()? as i128),
                    device,
                    fb.id.clone().map_or(Value::NotAvailable, Value::Str),
                    Value::Int(fb.size as i128),
                    Value::Str(format!("{}x{}", fb.xres_virtual, fb.yres_virtual)),
                    Value::Int(fb.bpp as i128),
                    Value::SStr(if state == 0 { "RUNNING" } else { "SUSPENDED" }),
                    file_output,
                ],
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn msb_right_reverses_bits() {
        let v: u128 = 0b0011;
        let bits = format!("{v:0width$b}", width = 5);
        assert_eq!(u128::from_str_radix(&bits.chars().rev().collect::<String>(), 2).unwrap(), 0b11000);
    }
}
