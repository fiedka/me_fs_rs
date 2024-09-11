use serde::{Deserialize, Serialize};
use std::mem;
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

// see https://github.com/peterbjornx/meimagetool ...intelme/model/fpt/ (Java)
// and https://github.com/platomav/MEAnalyzer (Python, good luck)

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct CodePartitionDirectory {
    // TODO
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
    pub header: FPT,
    pub entries: Vec<FPTEntry>,
}

pub fn parse(data: &[u8]) -> Result<ME_FPT, String> {
    let mut o = 16;

    while o + mem::size_of::<FPT>() <= data.len() {
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
                let me_fpt = ME_FPT {
                    header: fpt,
                    entries,
                };
                return Ok(me_fpt);
            }
        }
        o += 16;
    }
    Err("No $FPT :(".to_string())
}
