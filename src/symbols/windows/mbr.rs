//! python `symbols/windows/extensions/mbr.py`: `PARTITION_TABLE` / `PARTITION_ENTRY` of the
//! bundled `windows/mbr` ISF as views over a layer.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The `windows/mbr` table is fixed, so offsets and the `PartitionTypes` enum are constants here
//! (checked against the ISF by a unit test). `PARTITION_TABLE` (512 bytes): DiskSignature @440
//! (u8[4]), FirstEntry..FourthEntry @446/462/478/494, Signature @510. `PARTITION_ENTRY` (16
//! bytes): BootableFlag @0 u8, StartingCHS @1 u8[3], PartitionType @4 (`PartitionTypes`, u8),
//! EndingCHS @5 u8[3], StartingLBA @8 u32, SizeInSectors @12 u32. Every accessor reads where
//! python reads and returns `Err` where python raises.

use crate::error::{Error, Result};
use crate::layers::{Layer, LayerExt};

/// `PARTITION_TABLE.DiskSignature` offset.
pub const DISK_SIGNATURE: u64 = 440;
/// `PARTITION_TABLE.FirstEntry` offset (the entries follow each other, 16 bytes apart).
pub const FIRST_ENTRY: u64 = 446;
/// `PARTITION_ENTRY` size.
pub const ENTRY_SIZE: u64 = 16;

/// python `PartitionTypes.lookup(v)`; `None` = not a valid choice.
pub fn partition_type_name(v: u8) -> Option<&'static str> {
    Some(match v {
        0 => "Empty",
        1 => "FAT12,CHS",
        4 => "FAT16 16-32MB,CHS",
        5 => "Microsoft Extended",
        6 => "FAT16 32MB,CHS",
        7 => "NTFS",
        11 => "FAT32,CHS",
        12 => "FAT32,LBA",
        14 => "FAT16, 32MB-2GB,LBA",
        15 => "Microsoft Extended, LBA",
        17 => "Hidden FAT12,CHS",
        20 => "Hidden FAT16,16-32MB,CHS",
        22 => "Hidden FAT16,32MB-2GB,CHS",
        24 => "AST SmartSleep Partition",
        27 => "Hidden FAT32,CHS",
        28 => "Hidden FAT32,LBA",
        30 => "Hidden FAT16,32MB-2GB,LBA",
        39 => "PQservice",
        57 => "Plan 9 partition",
        60 => "PartitionMagic recovery partition",
        66 => "Microsoft MBR,Dynamic Disk",
        68 => "GoBack partition",
        81 => "Novell",
        82 => "CP/M",
        99 => "Unix System V",
        100 => "PC-ARMOUR protected partition",
        130 => "Solaris x86 or Linux Swap",
        131 => "Linux",
        133 => "Linux Extended",
        135 => "NTFS Volume Set",
        159 => "BSD/OS",
        161 => "Hibernation",
        165 => "FreeBSD",
        166 => "OpenBSD",
        168 => "Mac OSX",
        169 => "NetBSD",
        171 => "Mac OSX Boot",
        175 => "MacOS X HFS",
        183 => "BSDI",
        184 => "BSDI Swap",
        187 => "Boot Wizard hidden",
        190 => "Solaris 8 boot partition",
        216 => "CP/M-86",
        222 => "Dell PowerEdge Server utilities (FAT fs)",
        223 => "DG/UX virtual disk manager partition",
        235 => "BeOS BFS",
        238 => "EFI GPT Disk",
        239 => "EFI System Partition",
        251 => "VMWare File System",
        252 => "VMWare Swap",
        _ => return None,
    })
}

#[inline]
fn at(base: u64, rel: u64) -> Result<u64> {
    base.checked_add(rel).ok_or(Error::invalid(base))
}

/// python `mbr.PARTITION_TABLE` at `offset` of `layer`.
#[derive(Clone, Copy)]
pub struct PartitionTable<'a> {
    pub layer: &'a dyn Layer,
    pub offset: u64,
}

impl<'a> PartitionTable<'a> {
    pub fn new(layer: &'a dyn Layer, offset: u64) -> Self {
        PartitionTable { layer, offset }
    }

    /// python `get_disk_signature()`: the 4 `DiskSignature` bytes as `"xx-xx-xx-xx"`.
    pub fn get_disk_signature(&self) -> Result<String> {
        let b: [u8; 4] = self.layer.read_array(at(self.offset, DISK_SIGNATURE)?)?;
        Ok(format!("{:02x}-{:02x}-{:02x}-{:02x}", b[0], b[1], b[2], b[3]))
    }

    /// `FirstEntry` (0) .. `FourthEntry` (3).
    pub fn entry(&self, i: u64) -> PartitionEntry<'a> {
        PartitionEntry { layer: self.layer, offset: self.offset.wrapping_add(FIRST_ENTRY + i * ENTRY_SIZE) }
    }
}

/// python `mbr.PARTITION_ENTRY`.
#[derive(Clone, Copy)]
pub struct PartitionEntry<'a> {
    pub layer: &'a dyn Layer,
    pub offset: u64,
}

impl PartitionEntry<'_> {
    #[inline]
    fn u8_at(&self, rel: u64) -> Result<u8> {
        self.layer.read_u8(at(self.offset, rel)?)
    }

    /// python `get_bootable_flag()` (`BootableFlag`).
    pub fn get_bootable_flag(&self) -> Result<u8> {
        self.u8_at(0)
    }

    /// python `is_bootable()`: `BootableFlag == 0x80`.
    pub fn is_bootable(&self) -> Result<bool> {
        Ok(self.get_bootable_flag()? == 0x80)
    }

    /// `PartitionType` (raw value).
    pub fn partition_type(&self) -> Result<u8> {
        self.u8_at(4)
    }

    /// python `get_partition_type()`: the `PartitionTypes` name or "Not Defined PartitionType".
    pub fn get_partition_type(&self) -> Result<&'static str> {
        Ok(partition_type_name(self.partition_type()?).unwrap_or("Not Defined PartitionType"))
    }

    /// `StartingCHS[i]`.
    pub fn starting_chs(&self, i: u64) -> Result<u8> {
        self.u8_at(1 + i)
    }

    /// `EndingCHS[i]`.
    pub fn ending_chs(&self, i: u64) -> Result<u8> {
        self.u8_at(5 + i)
    }

    /// python `get_starting_chs()`: `StartingCHS[0]`.
    pub fn get_starting_chs(&self) -> Result<u8> {
        self.starting_chs(0)
    }

    /// python `get_ending_chs()`: `EndingCHS[0]`.
    pub fn get_ending_chs(&self) -> Result<u8> {
        self.ending_chs(0)
    }

    /// python `get_starting_sector()`: `StartingCHS[1] % 64`.
    pub fn get_starting_sector(&self) -> Result<u8> {
        Ok(self.starting_chs(1)? % 64)
    }

    /// python `get_ending_sector()`: `EndingCHS[1] % 64`.
    pub fn get_ending_sector(&self) -> Result<u8> {
        Ok(self.ending_chs(1)? % 64)
    }

    /// python `get_starting_cylinder()`: `(StartingCHS[1] - sector) * 4 + StartingCHS[2]`.
    pub fn get_starting_cylinder(&self) -> Result<u32> {
        let c1 = self.starting_chs(1)? as u32;
        let s = self.get_starting_sector()? as u32;
        Ok((c1 - s) * 4 + self.starting_chs(2)? as u32)
    }

    /// python `get_ending_cylinder()`: `(EndingCHS[1] - sector) * 4 + EndingCHS[2]`.
    pub fn get_ending_cylinder(&self) -> Result<u32> {
        let c1 = self.ending_chs(1)? as u32;
        let s = self.get_ending_sector()? as u32;
        Ok((c1 - s) * 4 + self.ending_chs(2)? as u32)
    }

    /// python `get_starting_lba()` (`StartingLBA`).
    pub fn get_starting_lba(&self) -> Result<u32> {
        self.layer.read_u32(at(self.offset, 8)?)
    }

    /// python `get_size_in_sectors()` (`SizeInSectors`).
    pub fn get_size_in_sectors(&self) -> Result<u32> {
        self.layer.read_u32(at(self.offset, 12)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isf_layout_matches() {
        let t = crate::symbols::load_isf("windows", "mbr", None, &[]).unwrap();
        let o = |ty: &str, m: &str| t.offset_of(ty, m).unwrap();
        assert_eq!(o("PARTITION_TABLE", "DiskSignature"), DISK_SIGNATURE);
        assert_eq!(o("PARTITION_TABLE", "FirstEntry"), FIRST_ENTRY);
        assert_eq!(o("PARTITION_TABLE", "SecondEntry"), FIRST_ENTRY + ENTRY_SIZE);
        assert_eq!(o("PARTITION_TABLE", "ThirdEntry"), FIRST_ENTRY + 2 * ENTRY_SIZE);
        assert_eq!(o("PARTITION_TABLE", "FourthEntry"), FIRST_ENTRY + 3 * ENTRY_SIZE);
        assert_eq!(o("PARTITION_ENTRY", "BootableFlag"), 0);
        assert_eq!(o("PARTITION_ENTRY", "StartingCHS"), 1);
        assert_eq!(o("PARTITION_ENTRY", "PartitionType"), 4);
        assert_eq!(o("PARTITION_ENTRY", "EndingCHS"), 5);
        assert_eq!(o("PARTITION_ENTRY", "StartingLBA"), 8);
        assert_eq!(o("PARTITION_ENTRY", "SizeInSectors"), 12);
        // mbr.json repeats keys ("Hibernation": 132, 160, 161; "NTFS Volume Set": 134, 135):
        // python's json keeps the LAST value of a duplicated key
        let e = t.enumeration("PartitionTypes").unwrap();
        let mut consts: Vec<(&str, i64)> = Vec::new();
        for (name, v) in t.enum_constants(e) {
            match consts.iter_mut().find(|c| c.0 == name) {
                Some(c) => c.1 = v,
                None => consts.push((name, v)),
            }
        }
        for &(name, v) in &consts {
            assert_eq!(partition_type_name(v as u8), Some(name), "{name} = {v}");
        }
        assert_eq!((0..=255u8).filter(|&v| partition_type_name(v).is_some()).count(), consts.len());
    }
}
