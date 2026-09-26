//! windows.registry.cachedump.Cachedump (python `plugins/windows/registry/cachedump.py`):
//! dumps cached domain credentials (MSCACHE).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! NOTE (crypto): the non-XP `decrypt_hash` reuses ONE AES-CBC cipher across all 16-byte
//! chunks — real chained CBC (`Aes::cbc_decrypt`), unlike lsadump's per-chunk fresh cipher.

use crate::context::Context;
use crate::crypto::aes::Aes;
use crate::crypto::{hmac, rc4::Rc4};
use crate::error::Result;
use crate::layers::registry::RegistryHive;
use crate::plugins::windows::registry::hashdump::{find_hives, get_bootkey, get_hive_key, read_value_data};
use crate::plugins::windows::registry::lsadump::{get_lsa_key, get_secret_by_name};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::registry::RegExt;
use crate::symbols::windows::versions;

pub struct Cachedump;

/// python `Cachedump.get_nlkm(sechive, lsakey, is_vista_or_later)`.
fn get_nlkm(sechive: &'static RegistryHive, lsakey: &[u8], vista: bool) -> Result<Option<Vec<u8>>> {
    get_secret_by_name(sechive, "NL$KM", lsakey, vista)
}

/// python `Cachedump.decrypt_hash(edata, nlkm, ch, xp)`.
fn decrypt_hash(edata: &[u8], nlkm: &[u8], ch: &[u8], xp: bool) -> Result<Vec<u8>> {
    if xp {
        let rc4key = hmac::hmac_md5(nlkm, ch);
        let mut data = edata.to_vec();
        Rc4::new(&rc4key).apply(&mut data);
        Ok(data)
    } else {
        // ONE cipher reused across chunks -> real chained CBC; short final chunk zero-padded
        let iv: [u8; 16] = ch[..16].try_into().unwrap();
        let mut padded = edata.to_vec();
        if !padded.len().is_multiple_of(16) {
            padded.resize(padded.len().div_ceil(16) * 16, 0);
        }
        let aes = Aes::new(&nlkm[16..32])?;
        aes.cbc_decrypt(&iv, &padded)
    }
}

/// python `Cachedump.parse_cache_entry(cache_data)`: (uname_len, domain_len, domain_name_len,
/// enc_data, ch).
fn parse_cache_entry(d: &[u8]) -> (u16, u16, u16, Vec<u8>, Vec<u8>) {
    let uname_len = u16::from_le_bytes([d[0], d[1]]);
    let domain_len = u16::from_le_bytes([d[2], d[3]]);
    if d.get(60..62).map(|s| s.len()).unwrap_or(0) == 0 {
        return (uname_len, domain_len, 0, Vec::new(), Vec::new());
    }
    let domain_name_len = u16::from_le_bytes([d[60], d[61]]);
    let ch = d[64..80.min(d.len())].to_vec();
    let enc_data = d[96.min(d.len())..].to_vec();
    (uname_len, domain_len, domain_name_len, enc_data, ch)
}

/// python `Cachedump.parse_decrypted_cache(dec_data, uname_len, domain_len, domain_name_len)`.
fn parse_decrypted_cache(dec: &[u8], uname_len: u16, domain_len: u16, domain_name_len: u16) -> (String, String, String) {
    let uname_offset = 72usize;
    let pad = 2 * ((uname_len as usize / 2) % 2);
    let domain_offset = uname_offset + uname_len as usize + pad;
    let pad = 2 * ((domain_len as usize / 2) % 2);
    let domain_name_offset = domain_offset + domain_len as usize + pad;
    let username = utf16le_replace(slice(dec, uname_offset, uname_len as usize));
    let domain = utf16le_replace(slice(dec, domain_offset, domain_len as usize));
    let domain_name = utf16le_replace(slice(dec, domain_name_offset, domain_name_len as usize));
    (username, domain, domain_name)
}

fn slice(d: &[u8], off: usize, len: usize) -> &[u8] {
    let start = off.min(d.len());
    let end = (off + len).min(d.len());
    &d[start..end]
}

/// python `bytes.decode("utf-16-le", "replace")`.
fn utf16le_replace(data: &[u8]) -> String {
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut s: String = char::decode_utf16(units).map(|r| r.unwrap_or('\u{FFFD}')).collect();
    // a trailing odd byte becomes a replacement char under python's "replace"
    if data.len() % 2 == 1 {
        s.push('\u{FFFD}');
    }
    s
}

fn generate(ctx: &Context, syshive: Option<&'static RegistryHive>, sechive: Option<&'static RegistryHive>, out: &mut dyn RowSink) -> Result<()> {
    let (Some(syshive), Some(sechive)) = (syshive, sechive) else { return Ok(()) };
    let bootkey = match get_bootkey(syshive)? {
        Some(b) => b,
        None => return Ok(()),
    };
    let k = ctx.windows_kernel()?;
    let vista = versions::IS_VISTA_OR_LATER.check(k.table);
    let lsakey = match get_lsa_key(sechive, &bootkey, vista)? {
        Some(k) => k,
        None => return Ok(()),
    };
    let nlkm = match get_nlkm(sechive, &lsakey, vista)? {
        Some(n) => n,
        None => return Ok(()),
    };
    let cache = match get_hive_key(sechive, "Cache")? {
        Some(c) => c,
        None => return Ok(()),
    };
    for cache_item in cache.get_values() {
        // python: `if cache_item.Name == "NL$Control": continue` compares an Array object to a
        // str, which is always False -> the NL$Control entry is filtered only by uname_len == 0.
        let data = match read_value_data(sechive, &cache_item) {
            Ok(d) => d,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        if data.is_empty() {
            continue;
        }
        let (uname_len, domain_len, domain_name_len, enc_data, ch) = parse_cache_entry(&data);
        if uname_len == 0 || ch.is_empty() {
            continue;
        }
        let dec_data = decrypt_hash(&enc_data, &nlkm, &ch, !vista)?;
        let (username, domain, domain_name) = parse_decrypted_cache(&dec_data, uname_len, domain_len, domain_name_len);
        let hashh = dec_data[..0x10.min(dec_data.len())].to_vec();
        out.row(0, vec![Value::Str(username), Value::Str(domain), Value::Str(domain_name), Value::Bytes(hashh)])?;
    }
    Ok(())
}

pub(crate) fn run_cachedump(ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
    out.begin(vec![
        Column::new("Username", ColType::Str),
        Column::new("Domain", ColType::Str),
        Column::new("Domain name", ColType::Str),
        Column::new("Hash", ColType::Bytes),
    ])?;
    let k = ctx.windows_kernel()?;
    let offset = cfg.get_int("offset").map(|o| o as u64);
    let hives = find_hives(ctx, k, offset)?;
    generate(ctx, hives.system, hives.security, out)
}

impl Plugin for Cachedump {
    fn name(&self) -> &'static str {
        "windows.registry.cachedump.Cachedump"
    }
    fn description(&self) -> &'static str {
        "Dumps lsa secrets from memory"
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_cachedump(ctx, cfg, out)
    }
}

/// Deprecated alias `windows.cachedump.Cachedump`.
pub struct CachedumpDeprecated;
impl Plugin for CachedumpDeprecated {
    fn name(&self) -> &'static str {
        "windows.cachedump.Cachedump"
    }
    fn description(&self) -> &'static str {
        "Dumps lsa secrets from memory (deprecated)"
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_cachedump(ctx, cfg, out)
    }
}
