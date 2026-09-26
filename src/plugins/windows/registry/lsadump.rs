//! windows.registry.lsadump.Lsadump (python `plugins/windows/registry/lsadump.py`): dumps LSA
//! secrets. Shared helpers [`decrypt_aes`], [`get_lsa_key`], [`get_secret_by_name`],
//! [`decrypt_secret`] are reused by cachedump.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! NOTE (crypto): `decrypt_aes` (LSA) creates a FRESH AES-CBC cipher per 16-byte chunk with a
//! zero IV — i.e. plain ECB (`Aes::ecb_decrypt`). This is NOT chained CBC; cachedump's
//! `decrypt_hash` reuses one cipher (real CBC, `Aes::cbc_decrypt`).

use crate::context::Context;
use crate::crypto::aes::Aes;
use crate::crypto::des::{Des, key_from_7_bytes};
use crate::crypto::{md5, rc4::Rc4, sha256::Sha256};
use crate::error::Result;
use crate::layers::registry::{RegistryHive, is_registry_exception};
use crate::objects::Obj;
use crate::plugins::windows::registry::hashdump::{find_hives, get_bootkey, read_value_data};
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::symbols::windows::registry::{RegExt, is_key_error};
use crate::symbols::windows::versions;

pub struct Lsadump;

fn get_hive_key(hive: &'static RegistryHive, key: &str) -> Result<Option<Obj>> {
    match hive.get_key_node(key) {
        Ok(n) => Ok(Some(n)),
        Err(e) if is_key_error(&e) || is_registry_exception(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// python `Lsadump.decrypt_aes(secret, key)`.
pub fn decrypt_aes(secret: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut sha = Sha256::new();
    sha.update(key);
    // python: for _ in range(1, 1001): sha.update(secret[28:60])  -> 1000 updates
    let block = if secret.len() >= 60 { &secret[28..60] } else { &secret[28.min(secret.len())..] };
    for _ in 0..1000 {
        sha.update(block);
    }
    let aeskey = sha.finalize();
    let aes = Aes::new(&aeskey)?;
    // fresh cipher per 16-byte chunk with zero IV == plain ECB; short final chunk zero-padded
    let start = 60.min(secret.len());
    Ok(aes.ecb_decrypt(&secret[start..]))
}

/// python `Lsadump.get_lsa_key(sechive, bootkey, vista_or_later)`.
pub fn get_lsa_key(sechive: &'static RegistryHive, bootkey: &[u8], vista_or_later: bool) -> Result<Option<Vec<u8>>> {
    let policy_key = if vista_or_later { "PolEKList" } else { "PolSecretEncryptionKey" };
    let enc_reg_key = match get_hive_key(sechive, &format!("Policy\\{policy_key}"))? {
        Some(k) => k,
        None => return Ok(None),
    };
    let enc_reg_value = match enc_reg_key.get_values().next() {
        Some(v) => v,
        None => return Ok(None),
    };
    let obf = match read_value_data(sechive, &enc_reg_value) {
        Ok(d) => d,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    if obf.is_empty() {
        return Ok(None);
    }
    if !vista_or_later {
        let mut m = md5::Md5::new();
        m.update(bootkey);
        for _ in 0..1000 {
            m.update(&obf[60..76]);
        }
        let rc4key = m.finalize();
        let mut lsa_key = obf[12..60].to_vec();
        Rc4::new(&rc4key).apply(&mut lsa_key);
        Ok(Some(lsa_key[0x10..0x20].to_vec()))
    } else {
        let lsa = decrypt_aes(&obf, bootkey)?;
        Ok(Some(lsa[68..100].to_vec()))
    }
}

/// python `Lsadump.get_secret_by_name(sechive, name, lsakey, is_vista_or_later)`.
pub fn get_secret_by_name(sechive: &'static RegistryHive, name: &str, lsakey: &[u8], vista: bool) -> Result<Option<Vec<u8>>> {
    let enc_secret_key = match get_hive_key(sechive, &format!("Policy\\Secrets\\{name}\\CurrVal"))? {
        Some(k) => k,
        None => return Ok(None),
    };
    let enc_secret_value = match get_first_value(&enc_secret_key) {
        Some(v) => v,
        None => return Ok(None),
    };
    let enc_secret = match read_value_data(sechive, &enc_secret_value) {
        Ok(d) => d,
        Err(e) if e.is_invalid_address() => return Ok(None),
        Err(e) => return Err(e),
    };
    if enc_secret.is_empty() {
        return Ok(None);
    }
    let secret = if !vista { decrypt_secret(&enc_secret[0xC..], lsakey) } else { decrypt_aes(&enc_secret, lsakey)? };
    Ok(Some(secret))
}

/// python `next(key.get_values(), None)` but suppressing InvalidAddress/Registry like the
/// call sites do.
fn get_first_value(key: &Obj) -> Option<Obj> {
    key.get_values().next()
}

/// python `Lsadump.decrypt_secret(secret, key)` (SystemFunction005).
pub fn decrypt_secret(secret: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::new();
    let mut j = 0usize;
    let mut i = 0usize;
    while i < secret.len() {
        let end = (i + 8).min(secret.len());
        let mut block = [0u8; 8];
        block[..end - i].copy_from_slice(&secret[i..end]);
        let key_end = (j + 7).min(key.len());
        let mut block_key = [0u8; 7];
        block_key[..key_end - j].copy_from_slice(&key[j..key_end]);
        let des_key = key_from_7_bytes(&block_key);
        let des = Des::new(&des_key);
        if let Ok(dec) = des.ecb_decrypt(&block) {
            decrypted.extend_from_slice(&dec);
        }
        j += 7;
        // python: if len(key[j:j+7]) < 7: j = len(key[j:j+7])
        let remaining = key.len().saturating_sub(j).min(7);
        if remaining < 7 {
            j = remaining;
        }
        i += 8;
    }
    if decrypted.len() < 4 {
        return Vec::new();
    }
    let dec_len = u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;
    let end = (8 + dec_len).min(decrypted.len());
    if 8 > decrypted.len() {
        return Vec::new();
    }
    decrypted[8..end].to_vec()
}

fn generate(ctx: &Context, syshive: Option<&'static RegistryHive>, sechive: Option<&'static RegistryHive>, out: &mut dyn RowSink) -> Result<()> {
    let k = ctx.windows_kernel()?;
    let vista = versions::IS_VISTA_OR_LATER.check(k.table);
    let (Some(syshive), Some(sechive)) = (syshive, sechive) else { return Ok(()) };
    let bootkey = match get_bootkey(syshive)? {
        Some(b) => b,
        None => return Ok(()), // "Unable to find bootkey"
    };
    let lsakey = match get_lsa_key(sechive, &bootkey, vista)? {
        Some(k) => k,
        None => return Ok(()), // "Unable to find lsa key"
    };
    let secrets_key = match get_hive_key(sechive, "Policy\\Secrets")? {
        Some(k) => k,
        None => return Ok(()), // "Unable to find secrets key"
    };
    for key in secrets_key.get_subkeys() {
        let key = key?;
        let path_part = key.get_key_path()?;
        let seg = path_part.split('\\').nth(3).unwrap_or("");
        let sec_val_key = match get_hive_key(sechive, &format!("Policy\\Secrets\\{seg}\\CurrVal"))? {
            Some(k) => k,
            None => continue,
        };
        let enc_secret_value = match sec_val_key.get_values().next() {
            Some(v) => v,
            None => continue,
        };
        let enc_secret = match read_value_data(sechive, &enc_secret_value) {
            Ok(d) => d,
            Err(e) if e.is_invalid_address() => continue,
            Err(e) => return Err(e),
        };
        let secret = if !vista { decrypt_secret(&enc_secret[0xC..], &lsakey) } else { decrypt_aes(&enc_secret, &lsakey)? };
        let key_name = match key.get_name() {
            Ok(n) => Value::Str(n),
            Err(e) if e.is_invalid_address() || is_registry_exception(&e) => Value::Unreadable,
            Err(e) => return Err(e),
        };
        out.row(0, vec![key_name, Value::Bytes(secret.clone()), Value::Bytes(secret)])?;
    }
    Ok(())
}

pub(crate) fn run_lsadump(ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
    out.begin(vec![
        Column::new("Key", ColType::Str),
        Column::new("Secret", ColType::HexBytes),
        Column::new("Hex", ColType::Bytes),
    ])?;
    let k = ctx.windows_kernel()?;
    let offset = cfg.get_int("offset").map(|o| o as u64);
    let hives = find_hives(ctx, k, offset)?;
    generate(ctx, hives.system, hives.security, out)
}

impl Plugin for Lsadump {
    fn name(&self) -> &'static str {
        "windows.registry.lsadump.Lsadump"
    }
    fn description(&self) -> &'static str {
        "Dumps lsa secrets from memory"
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_lsadump(ctx, cfg, out)
    }
}

/// Deprecated alias `windows.lsadump.Lsadump`.
pub struct LsadumpDeprecated;
impl Plugin for LsadumpDeprecated {
    fn name(&self) -> &'static str {
        "windows.lsadump.Lsadump"
    }
    fn description(&self) -> &'static str {
        "Dumps lsa secrets from memory (deprecated)"
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        run_lsadump(ctx, cfg, out)
    }
}
