use std::mem;
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

// see https://github.com/peterbjornx/meimagetool ...intelme/model/fpt/ (Java)
// and https://github.com/platomav/MEAnalyzer (Python, good luck)

#[derive(AsBytes, FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C)]
pub struct CodePartitionDirectory {
    // TODO
}

#[derive(AsBytes, FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C)]
pub struct FPTEntry {
    signature: [u8; 4],
    // TODO
    _rest: [u8; 28],
}

#[derive(AsBytes, FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C)]
pub struct FPT {
    pub signature: [u8; 4],
    pub entries: u32,
    pub header_ver: u32,
    pub entry_ver: u32,
    pub header_len: u32,
    pub checksum: u32,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
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
                    let pos = o + e * 32;
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
