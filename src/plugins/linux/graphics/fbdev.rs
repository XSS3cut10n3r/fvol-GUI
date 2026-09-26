//! linux.graphics.fbdev.Fbdev (python `plugins/linux/graphics/fbdev.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! `--dump` writes each framebuffer as a PNG (python converts it with pillow when the pixel
//! format is RGB-like; `codecs::png::png_rgba_pillow` writes pillow's exact bytes) or as the
//! raw buffer (FOURCC formats).

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
pub fn fb_raw_to_rgba(xres: u64, yres: u64, bits_per_pixel: u64, raw: &[u8], fields: &[(u32, u32, u32); 4]) -> Vec<u8> {
    let bpp = (bits_per_pixel / 8) as usize;
    let n = (xres * yres) as usize;
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
            let rgba = fb_raw_to_rgba(fb.xres_virtual, fb.yres_virtual, fb.bpp, &data, fields);
            if fb.xres_virtual == 0 || fb.yres_virtual == 0 {
                // pillow's `Image.save`
                return Err(crate::error::Error::msg("ValueError: cannot write empty image"));
            }
            // pillow's `image.save(BytesIO, "PNG")`, byte for byte
            (crate::codecs::png::png_rgba_pillow(fb.xres_virtual as u32, fb.yres_virtual as u32, &rgba), format!("{base}.png"))
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
    use super::fb_raw_to_rgba;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn dump_png_like_python_pillow() {
        // expected: python's convert_fb_raw_buffer_to_image(...) + image.save(BytesIO, "PNG")
        // (pillow 12.3.0 / zlib 1.3.2)
        let raw: Vec<u8> = (0..60u32).map(|i| ((i * 37 + 11) & 255) as u8).collect();
        let xrgb = [(16, 8, 0), (8, 8, 0), (0, 8, 0), (0, 0, 0)];
        let png = crate::codecs::png::png_rgba_pillow(5, 3, &fb_raw_to_rgba(5, 3, 32, &raw, &xrgb));
        assert_eq!(hex(&png), "89504e470d0a1a0a0000000d49484452000000050000000308060000005b36c5f80000002749444154789c630835e0fefff2c8fcffb511c6ff05df1cffbfb421fa3fd393274f18d031564100b3c826e02e01bd440000000049454e44ae426082");
        let raw2: Vec<u8> = (0..56u32).map(|i| ((i * i * 7 + 3) & 255) as u8).collect();
        let rgb565 = [(11, 5, 0), (5, 6, 0), (0, 5, 0), (0, 0, 0)];
        let png2 = crate::codecs::png::png_rgba_pillow(7, 4, &fb_raw_to_rgba(7, 4, 16, &raw2, &rgb565));
        assert_eq!(hex(&png2), "89504e470d0a1a0a0000000d494844520000000700000004080600000042c6257d0000005e49444154789c05c1510e82400c40c1d7ed024a1a4324fcf5fe27eb11aa68dc50674436ad05e7a1c9ab1ba3022d676d49ebcd390866354e92dbcff94ab00e43d8f7ba8bb18de0ecce55c984611ab4e765a826393bd308de652c3df994f3071a9021c94ca002f10000000049454e44ae426082");
    }

    #[test]
    fn raw_to_rgba_like_python_putpixel() {
        // expected: python's convert_fb_raw_buffer_to_image(...).tobytes() (pillow 12.3.0)
        let raw: Vec<u8> = (0..64u32).map(|i| ((i * 37 + 11) & 255) as u8).collect();
        let xrgb = [(16, 8, 0), (8, 8, 0), (0, 8, 0), (0, 0, 0)];
        assert_eq!(hex(&fb_raw_to_rgba(3, 2, 32, &raw, &xrgb)), "55300bffe9c49fff7d5833ff11ecc7ffa5805bff3914efff");
        let rgb565 = [(11, 5, 0), (5, 6, 1), (0, 5, 0), (0, 0, 0)];
        assert_eq!(hex(&fb_raw_to_rgba(4, 2, 16, &raw, &rgb565)), "06000bff0f1215ff18091fff013b09ff0b2013ff14321dff1d1907ff060311ff");
        let short = [(0, 8, 1), (8, 8, 0), (16, 8, 0), (20, 4, 0)];
        assert_eq!(hex(&fb_raw_to_rgba(3, 2, 24, &raw[..10], &short)), "d03055055e9fc40c970e33031a0000000000000000000000");
        let wide = [(0, 12, 0), (12, 10, 0), (22, 10, 1), (30, 2, 0)];
        assert_eq!(hex(&fb_raw_to_rgba(2, 2, 32, &raw, &wide)), "0bffff01ffffff00ffffff02ffff6c00");
    }

    #[test]
    fn msb_right_reverses_bits() {
        let v: u128 = 0b0011;
        let bits = format!("{v:0width$b}", width = 5);
        assert_eq!(u128::from_str_radix(&bits.chars().rev().collect::<String>(), 2).unwrap(), 0b11000);
    }
}
