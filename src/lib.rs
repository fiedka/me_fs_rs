use serde::{Deserialize, Serialize};
use std::mem;
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

// see https://github.com/peterbjornx/meimagetool ...intelme/model/fpt/ (Java)
// and https://github.com/platomav/MEAnalyzer (Python, good luck)

// see https://troopers.de/downloads/troopers17/TR17_ME11_Static.pdf
#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct CPDHeader {
    pub magic: [u8; 4],
    pub entries: u32,
    pub version_or_checksum: u32,
    pub part_name: [u8; 4],
}

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct CPDEntry {
    pub name: [u8; 12],
    pub offset: u32,
    pub size: u32,
    pub compression_flag: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct CodePartitionDirectory {
    pub header: CPDHeader,
    pub entries: Vec<CPDEntry>,
}

// see https://github.com/linuxboot/fiano/blob/main/pkg/intel/me/structures.go
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

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct FitcVer {
    pub major: u16,
    pub minor: u16,
    pub hotfix: u16,
    pub build: u16,
}

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
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PartitionType {
    Code,
    Data,
    None,
}

// see https://troopers.de/downloads/troopers17/TR17_ME11_Static.pdf
pub fn get_part_info(n: &str) -> (PartitionType, &str) {
    match n {
        "FTPR" => (PartitionType::Code, "Main code partition"),
        "FTUP" => (PartitionType::Code, "[NFTP]+[WCOD]+[LOCL]"),
        "DLMP" => (PartitionType::Code, "IDLM partition"),
        "PSVN" => (PartitionType::Data, "Secure Version Number"),
        "IVBP" => (PartitionType::Data, "IV + Bring Up cache"),
        "MFS" => (PartitionType::Data, "ME Flash File System"),
        "NFTP" => (PartitionType::Code, "Additional code"),
        "ROMB" => (PartitionType::Code, "ROM Bypass"),
        "WCOD" => (PartitionType::Code, "WLAN uCode"),
        "LOCL" => (PartitionType::Code, "AMT Localization"),
        "FLOG" => (PartitionType::Data, "Flash Log"),
        "UTOK" => (PartitionType::Data, "Debug Unlock Token"),
        "ISHC" => (PartitionType::Code, "Integrated Sensors Hub"),
        _ => (PartitionType::None, ""),
    }
}

pub fn parse_cpd(data: &[u8]) -> Result<CodePartitionDirectory, String> {
    let header = CPDHeader::read_from_prefix(data).unwrap();
    let mut entries = Vec::<CPDEntry>::new();
    for e in 0..header.entries as usize {
        let pos = 16 + e * 24;
        let entry = CPDEntry::read_from_prefix(&data[pos..]).unwrap();
        entries.push(entry);
    }
    let cpd = CodePartitionDirectory { header, entries };
    Ok(cpd)
}

pub fn parse(data: &[u8]) -> Result<ME_FPT, String> {
    let mut b = 0;

    while b + 16 + mem::size_of::<FPT>() <= data.len() {
        // first 16 bytes are potentially other stuff
        let o = b + 16;
        let buf = &data[o..o + 32];
        if let Ok(s) = std::str::from_utf8(&buf[..8]) {
            if s.starts_with("$FPT") {
                let fpt = FPT::read_from_prefix(&data[o..]).unwrap();
                let mut entries = Vec::<FPTEntry>::new();
                for e in 0..fpt.entries as usize {
                    // NOTE: Skip $FPT itself
                    let pos = o + 32 + e * 32;
                    let entry = FPTEntry::read_from_prefix(&data[pos..]).unwrap();
                    entries.push(entry);
                }

                // realign base
                if b % 0x1000 != 0 {
                    println!("realign");
                    b = o;
                }

                let mut directories = Vec::<CodePartitionDirectory>::new();
                for e in &entries {
                    let n = std::str::from_utf8(&e.name).unwrap();
                    if n == "FTPR" || n == "NFTP" {
                        let o = b + e.offset as usize;
                        let s = e.size as usize;

                        let buf = &data[o..o + 4];
                        if let Ok(sig) = std::str::from_utf8(buf) {
                            let sig = sig.trim_end_matches(char::from(0));
                            if sig == "$CPD" {
                                let cpd = parse_cpd(&data[o..o + s]).unwrap();
                                directories.push(cpd);
                            }
                        }
                    }
                }

                let me_fpt = ME_FPT {
                    base: b,
                    header: fpt,
                    entries,
                    directories,
                };
                return Ok(me_fpt);
            }
        }
        b += 16;
    }
    Err("No $FPT :(".to_string())
}
