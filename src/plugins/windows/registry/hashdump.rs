//! windows.registry.hashdump.Hashdump (python `plugins/windows/registry/hashdump.py`): dumps
//! user password hashes from the SAM/SYSTEM hives. Shared SAM/SYSTEM helpers
//! ([`get_hive_key`], [`get_bootkey`], [`get_hbootkey`], [`get_user_keys`], [`sid_to_key`]) are
//! reused by lsadump and cachedump.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::context::Context;
use crate::crypto::{aes::Aes, des::Des, des::key_from_7_bytes, md5, rc4::Rc4};
use crate::error::{Error, Result};
use crate::layers::registry::{RegistryHive, is_registry_exception};
use crate::objects::Obj;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::registry::{RegExt, is_key_error};

pub struct Hashdump;

// python's constant byte strings
const AQWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const ANUM: &[u8] = b"0123456789012345678901234567890123456789\0";
const ANTPASSWORD: &[u8] = b"NTPASSWORD\0";
const ALMPASSWORD: &[u8] = b"LMPASSWORD\0";
pub const EMPTY_LM: [u8; 16] = [0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee];
pub const EMPTY_NT: [u8; 16] = [0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0];

const BOOTKEY_PERM: [usize; 16] = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7];

/// python `Hashdump.get_hive_key(hive, key)`: the key node, or None on KeyError /
/// RegistryException (InvalidAddressException propagates, like python).
pub fn get_hive_key(hive: &'static RegistryHive, key: &str) -> Result<Option<Obj>> {
    match hive.get_key_node(key) {
        Ok(n) => Ok(Some(n)),
        Err(e) if is_key_error(&e) || is_registry_exception(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read a `_CM_KEY_NODE.Class` blob: `hive.read(Class + 4, ClassLength)`.
fn read_class(hive: &RegistryHive, key: &Obj) -> Result<Vec<u8>> {
    let class = key.m("Class")?.u64()?;
    let len = key.m("ClassLength")?.u64()?;
    hive.read_bytes(class + 4, len)
}

/// Read a `_CM_KEY_VALUE.Data` blob: `hive.read(Data + 4, DataLength)`.
pub fn read_value_data(hive: &RegistryHive, value: &Obj) -> Result<Vec<u8>> {
    let data = value.m("Data")?.u64()?;
    let len = value.m("DataLength")?.u64()?;
    hive.read_bytes(data + 4, len)
}

fn decode_utf16le(data: &[u8]) -> Result<String> {
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    char::decode_utf16(units).collect::<std::result::Result<String, _>>().map_err(|_| Error::msg("UnicodeDecodeError: invalid utf-16"))
}

/// python `Hashdump.get_bootkey(syshive)`: the scrambled boot key (None when a required Lsa key
/// is missing or unreadable).
pub fn get_bootkey(syshive: &'static RegistryHive) -> Result<Option<[u8; 16]>> {
    let lsa_base = "ControlSet001\\Control\\Lsa";
    let lsa = match get_hive_key(syshive, lsa_base)? {
        Some(_) => (),
        None => return Ok(None),
    };
    let _ = lsa;
    let mut bootkey = String::new();
    for lk in ["JD", "Skew1", "GBG", "Data"] {
        let key = match get_hive_key(syshive, &format!("{lsa_base}\\{lk}")) {
            Ok(Some(k)) => k,
            Ok(None) => return Ok(None),
            Err(e) if e.is_invalid_address() || is_registry_exception(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        let class_data = match read_class(syshive, &key) {
            Ok(d) => d,
            Err(e) if e.is_invalid_address() => return Ok(None),
            Err(e) if is_registry_exception(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        bootkey.push_str(&decode_utf16le(&class_data)?);
    }
    let raw = match unhexlify(&bootkey) {
        Some(r) if r.len() == 16 => r,
        _ => return Ok(None),
    };
    let mut scrambled = [0u8; 16];
    for i in 0..16 {
        scrambled[i] = raw[BOOTKEY_PERM[i]];
    }
    Ok(Some(scrambled))
}

fn unhexlify(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// python `Hashdump.get_hbootkey(samhive, bootkey)`.
pub fn get_hbootkey(samhive: &'static RegistryHive, bootkey: &[u8; 16]) -> Result<Option<Vec<u8>>> {
    let sam_account = match get_hive_key(samhive, "SAM\\Domains\\Account")? {
        Some(k) => k,
        None => return Ok(None),
    };
    let mut sam_data = None;
    for v in sam_account.get_values() {
        if v.get_name()? == "F" {
            match read_value_data(samhive, &v) {
                Ok(d) => sam_data = Some(d),
                Err(e) if e.is_invalid_address() => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
    let sam_data = match sam_data {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(None),
    };
    let revision = sam_data[0];
    if revision == 2 {
        let mut buf = Vec::new();
        buf.extend_from_slice(&sam_data[0x70..0x80]);
        buf.extend_from_slice(AQWERTY);
        buf.extend_from_slice(bootkey);
        buf.extend_from_slice(ANUM);
        let rc4_key = md5::digest(&buf);
        let mut hbootkey = sam_data[0x80..0xA0].to_vec();
        Rc4::new(&rc4_key).apply(&mut hbootkey);
        Ok(Some(hbootkey))
    } else if revision == 3 {
        let iv: [u8; 16] = sam_data[0x78..0x88].try_into().unwrap();
        let enc = &sam_data[0x88..0xA8];
        let cipher = Aes::new(bootkey)?;
        let hbootkey = cipher.cbc_decrypt(&iv, enc)?;
        Ok(Some(hbootkey[..16].to_vec()))
    } else {
        Ok(None)
    }
}

/// python `Hashdump.get_user_keys(samhive)`: the user subkeys (name != "Names").
pub fn get_user_keys(samhive: &'static RegistryHive) -> Result<Vec<Obj>> {
    let user_key = match get_hive_key(samhive, "SAM\\Domains\\Account\\Users")? {
        Some(k) => k,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for k in user_key.get_subkeys() {
        let k = k?;
        if k.get_name()? != "Names" {
            out.push(k);
        }
    }
    Ok(out)
}

/// python `Hashdump.sid_to_key(sid)`.
pub fn sid_to_key(sid: u32) -> ([u8; 8], [u8; 8]) {
    let s = sid;
    let b1 = [(s & 0xFF) as u8, ((s >> 8) & 0xFF) as u8, ((s >> 16) & 0xFF) as u8, ((s >> 24) & 0xFF) as u8];
    let str1 = [b1[0], b1[1], b1[2], b1[3], b1[0], b1[1], b1[2]];
    let str2 = [b1[3], b1[0], b1[1], b1[2], b1[3], b1[0], b1[1]];
    (key_from_7_bytes(&str1), key_from_7_bytes(&str2))
}

/// python `Hashdump.decrypt_single_hash(rid, hbootkey, enc_hash, lmntstr)`.
fn decrypt_single_hash(rid: u32, hbootkey: &[u8], enc_hash: &[u8], lmntstr: &[u8]) -> Result<Vec<u8>> {
    let (k1, k2) = sid_to_key(rid);
    let des1 = Des::new(&k1);
    let des2 = Des::new(&k2);
    let mut buf = Vec::new();
    buf.extend_from_slice(&hbootkey[..0x10]);
    buf.extend_from_slice(&(rid).to_le_bytes());
    buf.extend_from_slice(lmntstr);
    let rc4_key = md5::digest(&buf);
    let mut obfkey = enc_hash.to_vec();
    Rc4::new(&rc4_key).apply(&mut obfkey);
    let mut out = des1.ecb_decrypt(&obfkey[..8])?;
    out.extend(des2.ecb_decrypt(&obfkey[8..])?);
    Ok(out)
}

/// python `Hashdump.decrypt_single_salted_hash(rid, hbootkey, enc_hash, _lmntstr, salt)`.
fn decrypt_single_salted_hash(rid: u32, hbootkey: &[u8], enc_hash: &[u8], salt: &[u8; 16]) -> Result<Vec<u8>> {
    let (k1, k2) = sid_to_key(rid);
    let des1 = Des::new(&k1);
    let des2 = Des::new(&k2);
    let cipher = Aes::new(&hbootkey[..16])?;
    let obfkey = cipher.cbc_decrypt(salt, enc_hash)?;
    let mut out = des1.ecb_decrypt(&obfkey[..8])?;
    out.extend(des2.ecb_decrypt(&obfkey[8..16])?);
    Ok(out)
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// python `Hashdump.get_user_hashes(user, samhive, hbootkey)`: (lmhash, nthash) or None.
fn get_user_hashes(user: &Obj, samhive: &'static RegistryHive, hbootkey: &[u8]) -> Result<Option<(Option<Vec<u8>>, Option<Vec<u8>>)>> {
    let rid = match u32::from_str_radix(user.get_name()?.trim(), 16) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let mut sam_data = None;
    for v in user.get_values() {
        if v.get_name()? == "V" {
            match read_value_data(samhive, &v) {
                Ok(d) => sam_data = Some(d),
                Err(e) if e.is_invalid_address() || is_registry_exception(&e) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
    let sam_data = match sam_data {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(None),
    };
    let lm_offset = (u32le(&sam_data, 0x9C) + 0xCC) as usize;
    let lm_len = u32le(&sam_data, 0xA0);
    let nt_offset = (u32le(&sam_data, 0xA8) + 0xCC) as usize;
    let nt_len = u32le(&sam_data, 0xAC);

    let mut lmhash = None;
    match sam_data.get(lm_offset + 2) {
        Some(1) if lm_len == 20 => {
            let enc = &sam_data[lm_offset + 0x04..lm_offset + 0x14];
            lmhash = Some(decrypt_single_hash(rid, hbootkey, enc, ALMPASSWORD)?);
        }
        Some(2) if lm_len == 56 => {
            let salt: [u8; 16] = sam_data[lm_offset + 4..lm_offset + 20].try_into().unwrap();
            let enc = &sam_data[lm_offset + 20..lm_offset + 52];
            lmhash = Some(decrypt_single_salted_hash(rid, hbootkey, enc, &salt)?);
        }
        _ => {}
    }
    let mut nthash = None;
    match sam_data.get(nt_offset + 2) {
        Some(1) if nt_len == 20 => {
            let enc = &sam_data[nt_offset + 4..nt_offset + 20];
            nthash = Some(decrypt_single_hash(rid, hbootkey, enc, ANTPASSWORD)?);
        }
        Some(2) if nt_len == 56 => {
            let salt: [u8; 16] = sam_data[nt_offset + 8..nt_offset + 24].try_into().unwrap();
            let enc = &sam_data[nt_offset + 24..nt_offset + 56];
            nthash = Some(decrypt_single_salted_hash(rid, hbootkey, enc, &salt)?);
        }
        _ => {}
    }
    Ok(Some((lmhash, nthash)))
}

/// python `Hashdump.get_user_name(user, samhive)`: the raw username bytes, or None.
fn get_user_name(user: &Obj, samhive: &'static RegistryHive) -> Result<Option<Vec<u8>>> {
    let mut value = None;
    for v in user.get_values() {
        if v.get_name()? == "V" {
            match read_value_data(samhive, &v) {
                Ok(d) => value = Some(d),
                Err(e) if e.is_invalid_address() => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
    let value = match value {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(None),
    };
    let name_offset = (u32le(&value, 0x0C) + 0xCC) as usize;
    let name_length = u32le(&value, 0x10) as usize;
    if name_length > value.len() {
        return Ok(None);
    }
    Ok(Some(value[name_offset..name_offset + name_length].to_vec()))
}

fn hexlify(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// utf-16-le decode with errors="ignore" (python `str(bytes, "utf-16-le", errors="ignore")`).
fn utf16le_ignore(data: &[u8]) -> String {
    let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    char::decode_utf16(units).filter_map(|r| r.ok()).collect()
}

/// The SYSTEM / SAM / SECURITY hives (python `run()` selection by name suffix).
pub fn find_hives(ctx: &Context, k: &crate::context::WinKernel, offset: Option<u64>) -> Result<HiveSet> {
    let offsets = offset.map(|o| vec![o]);
    let mut set = HiveSet::default();
    for h in super::hivelist::list_hives(ctx, k, None, offsets.as_deref()) {
        let hive = h?;
        let last = hive.get_name().rsplit('\\').next().unwrap_or("").to_uppercase();
        match last.as_str() {
            "SYSTEM" => set.system = Some(hive),
            "SAM" => set.sam = Some(hive),
            "SECURITY" => set.security = Some(hive),
            _ => {}
        }
    }
    Ok(set)
}

#[derive(Default)]
pub struct HiveSet {
    pub system: Option<&'static RegistryHive>,
    pub sam: Option<&'static RegistryHive>,
    pub security: Option<&'static RegistryHive>,
}

fn generate(syshive: Option<&'static RegistryHive>, samhive: Option<&'static RegistryHive>, out: &mut dyn RowSink) -> Result<()> {
    let (Some(syshive), Some(samhive)) = (syshive, samhive) else { return Ok(()) };
    let bootkey = match get_bootkey(syshive)? {
        Some(b) => b,
        None => return Ok(()),
    };
    let hbootkey = match get_hbootkey(samhive, &bootkey)? {
        Some(h) => h,
        None => return Ok(()), // python: vollog.warning("Hbootkey is not valid")
    };
    for user in get_user_keys(samhive)? {
        let Some((lmhash, nthash)) = get_user_hashes(&user, samhive, &hbootkey)? else { continue };
        let name = match get_user_name(&user, samhive)? {
            Some(n) => Value::Str(utf16le_ignore(&n)),
            None => Value::NotAvailable,
        };
        let lmout = hexlify(lmhash.as_deref().unwrap_or(&EMPTY_LM));
        let ntout = hexlify(nthash.as_deref().unwrap_or(&EMPTY_NT));
        let rid = u32::from_str_radix(user.get_name()?.trim(), 16).map_err(|_| Error::msg("invalid rid"))?;
        out.row(0, vec![name, Value::Int(rid as i128), Value::Str(lmout), Value::Str(ntout)])?;
    }
    Ok(())
}

pub(crate) fn run_hashdump(ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
    out.begin(vec![
        Column::new("User", ColType::Str),
        Column::new("rid", ColType::Int),
        Column::new("lmhash", ColType::Str),
        Column::new("nthash", ColType::Str),
    ])?;
    let k = ctx.windows_kernel()?;
    let offset = cfg.get_int("offset").map(|o| o as u64);
    let hives = find_hives(ctx, k, offset)?;
    generate(hives.system, hives.sam, out)
}

impl Plugin for Hashdump {
    fn name(&self) -> &'static str {
        "windows.registry.hashdump.Hashdump"
    }
    fn description(&self) -> &'static str {
        "Dumps user hashes from memory"
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_hashdump(ctx, cfg, out)
    }
}

/// Deprecated alias `windows.hashdump.Hashdump`.
pub struct HashdumpDeprecated;
impl Plugin for HashdumpDeprecated {
    fn name(&self) -> &'static str {
        "windows.hashdump.Hashdump"
    }
    fn description(&self) -> &'static str {
        "Dumps user hashes from memory (deprecated)"
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_hashdump(ctx, cfg, out)
    }
}
