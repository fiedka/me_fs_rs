use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

use crate::dir::gen2::Directory as Gen2Directory;
use crate::dir::gen3::CodePartitionDirectory;
use crate::fit::Fit;

// see https://github.com/peterbjornx/meimagetool ...intelme/model/fpt/ (Java)
// and https://github.com/linuxboot/fiano/blob/main/pkg/intel/me/structures.go
// and https://github.com/platomav/MEAnalyzer (Python, good luck)
#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct FPTEntry {
    pub name: [u8; 4],
    pub owner: [u8; 4],
    pub offset: u32,
    pub size: u32,
    pub start_tokens: u32,
    pub max_tokens: u32,
    pub scratch_sectors: u32,
    pub flags: u32,
}

impl Display for FPTEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.offset as usize;
        let s = self.size as usize;
        let end = o + s;

        let name = match std::str::from_utf8(&self.name) {
            Ok(n) => n.trim_end_matches('\0').to_string(),
            Err(_) => format!("{:02x?}", &self.name),
        };

        let (part_type, full_name) = get_part_info(name.as_str());
        let part_info = format!("{part_type:?}: {full_name}");
        let name_offset_end_size = format!("{name:>4} @ 0x{o:08x}:0x{end:08x} (0x{s:08x})");

        write!(f, "{name_offset_end_size}  {part_info}")
    }
}

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct FitcVer {
    pub major: u16,
    pub minor: u16,
    pub hotfix: u16,
    pub build: u16,
}

// ...
pub const FPT_MAGIC: &str = "$FPT";

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct FPT {
    pub signature: [u8; 4],
    pub entries: u32,
    pub header_ver: u8,
    pub entry_ver: u8,
    pub header_len: u8,
    pub checksum: u8,
    pub ticks_to_add: u16,
    pub tokens_to_add: u16,
    pub uma_size_or_reserved: u32,
    pub flash_layout_or_flags: u32,
    // Not Present in ME version 7
    pub fitc_ver: FitcVer,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ME_FPT {
    pub base: usize,
    pub header: FPT,
    pub entries: Vec<FPTEntry>,
    pub directories: Vec<CodePartitionDirectory>,
    pub gen2dirs: Vec<Gen2Directory>,
    pub fit: Result<Fit, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PartitionType {
    Code,
    Data,
    None,
}

pub const FTUP: u32 = u32::from_be_bytes(*b"FTUP");
pub const DLMP: u32 = u32::from_be_bytes(*b"DLMP");
pub const FTPR: u32 = u32::from_be_bytes(*b"FTPR");
pub const NFTP: u32 = u32::from_be_bytes(*b"NFTP");
pub const MDMV: u32 = u32::from_be_bytes(*b"MDMV");

pub const MFS: u32 = u32::from_be_bytes(*b"MFS\0");
pub const AFSP: u32 = u32::from_be_bytes(*b"AFSP");
pub const EFFS: u32 = u32::from_be_bytes(*b"EFFS");

// see https://troopers.de/downloads/troopers17/TR17_ME11_Static.pdf
pub fn get_part_info(n: &str) -> (PartitionType, &str) {
    match n {
        "FTPR" => (PartitionType::Code, "Main code partition"),
        "FTUP" => (PartitionType::Code, "[NFTP]+[WCOD]+[LOCL]"),
        "DLMP" => (PartitionType::Code, "IDLM partition"),
        "PSVN" => (PartitionType::Data, "Secure Version Number"),
        // IVBP used in hibernation
        "IVBP" => (PartitionType::Data, "IV + Bring Up cache"),
        "MFS" => (PartitionType::Data, "ME Flash File System"),
        "NFTP" => (PartitionType::Code, "Additional code"),
        "ROMB" => (PartitionType::Code, "ROM Bypass"),
        "WCOD" => (PartitionType::Code, "WLAN uCode"),
        "LOCL" => (PartitionType::Code, "AMT Localization"),
        "FLOG" => (PartitionType::Data, "Flash Log"),
        "UTOK" => (PartitionType::Data, "Debug Unlock Token"),
        "ISHC" => (PartitionType::Code, "Integrated Sensors Hub"),
        "AFSP" => (PartitionType::None, "8778 55aa signature like MFS"),
        "FTPM" => (PartitionType::Code, "Firmware TPM (unconfirmed)"),
        "GLUT" => (PartitionType::Data, "Huffman Look-Up Table"),
        "EFFS" => (PartitionType::Data, "EFFS File System"),
        "FOVD" => (PartitionType::Data, "FOVD..."),
        _ => (PartitionType::None, "[> UNKNOWN <]"),
    }
}

/*
Some entries here have 8 byte magics or XXID...?
EFFS - embedded flash file system (?)
FOVD - ???; also on Skochinsky's slides, see
https://recon.cx/2014/slides/Recon%202014%20Skochinsky.pdf
NVCL and some other have lots of ffff...?
~/firmware/XMG/C404/extracted/BIOS/BIOS.BIN/XMGBF.B05

NVCL, NVCP, NVHM, NVKR, NVSH etc _and their values_ also appears in MFS!!!
also PLDM, BIAL, ...

00001000: 2020 800f 4000 0024 0000 0000 0000 0000    ..@..$........
00001010: 2446 5054 1300 0000 2010 30f7 0700 6400  $FPT.... .0...d.
00001020: 1000 0000 01fc ffff 0900 0000 1600 bb05  ................
00001030: 5053 564e 4b52 4944 c00b 0000 4000 0000  PSVNKRID....@...
00001040: 0100 0000 0100 0000 0000 0000 8387 0100  ................
00001050: 464f 5644 4b52 4944 000c 0000 0004 0000  FOVDKRID........
00001060: 0100 0000 0100 0000 0000 0000 8307 0000  ................
00001070: 4d44 4553 4d44 4944 0010 0000 0010 0000  MDESMDID........
00001080: 0100 0000 0100 0000 0000 0000 8323 0000  .............#..
00001090: 4643 5253 4f53 4944 0020 0000 0010 0000  FCRSOSID. ......
000010a0: 0100 0000 0100 0000 0000 0000 8323 0000  .............#..
000010b0: 4546 4653 4f53 4944 0030 0000 0000 0400  EFFSOSID.0......
000010c0: 400b 0000 6027 0000 0000 0000 04a7 0000  @...`'..........
000010d0: 4e56 434c ffff ffff ffff ffff c969 0000  NVCL.........i.. // immediate value?
000010e0: ffff ffff ffff ffff ffff ffff 0200 0000  ................ // 2 = value size?
000010f0: 4e56 4350 ffff ffff ffff ffff c0a3 0000  NVCP............
00001100: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001110: 4e56 484d ffff ffff ffff ffff 5800 0000  NVHM........X...
00001120: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001130: 4e56 4a43 ffff ffff ffff ffff a03d 0000  NVJC.........=..
00001140: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001150: 4e56 4b52 ffff ffff ffff ffff 305c 0000  NVKR........0\..
00001160: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001170: 4e56 4e46 ffff ffff ffff ffff 5f17 0000  NVNF........_...
00001180: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001190: 4e56 5348 ffff ffff ffff ffff c022 0000  NVSH........."..
000011a0: ffff ffff ffff ffff ffff ffff 0200 0000  ................
000011b0: 4e56 534d ffff ffff ffff ffff e81d 0000  NVSM............
000011c0: ffff ffff ffff ffff ffff ffff 0200 0000  ................
000011d0: 4e56 5444 ffff ffff ffff ffff eb1f 0000  NVTD............
000011e0: ffff ffff ffff ffff ffff ffff 0200 0000  ................
000011f0: 4e56 554b ffff ffff ffff ffff 4089 0000  NVUK........@...
00001200: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001210: 474c 5554 ffff ffff 0030 0400 0040 0000  GLUT.....0...@..
00001220: 0100 0000 0100 0000 0000 0000 83a7 0000  ................
00001230: 4654 5052 ffff ffff 0070 0400 0080 0800  FTPR.....p......
00001240: 0100 0000 0100 0000 0000 0000 80a7 0000  ................
00001250: 4e46 5450 ffff ffff 00f0 0c00 0070 0700  NFTP.........p..
00001260: 0100 0000 0100 0000 0000 0000 80a7 0000  ................
00001270: 4d44 4d56 ffff ffff 0060 1400 0070 0300  MDMV.....`...p..
00001280: 0100 0000 0100 0000 0000 0000 80a7 0000  ................
*/
