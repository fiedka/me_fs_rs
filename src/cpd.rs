use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

pub const CPD_MAGIC: &str = "$CPD";

// see https://troopers.de/downloads/troopers17/TR17_ME11_Static.pdf
#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct CPDHeader {
    pub magic: [u8; 4],
    pub entries: u32,
    pub version_or_checksum: u32,
    pub part_name: [u8; 4],
    // Some ME variants have an extra 4 bytes here...
    // _10: u32,
}

const HEADER_SIZE: usize = core::mem::size_of::<CPDHeader>();

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct CPDEntry {
    pub name: [u8; 12],
    pub offset: u32,
    pub size: u32,
    pub compression_flag: u32,
}

impl CPDEntry {
    pub fn name(&self) -> String {
        match std::str::from_utf8(&self.name) {
            Ok(n) => n.trim_end_matches('\0').to_string(),
            Err(_) => format!("{:02x?}", &self.name),
        }
    }
}

impl Display for CPDEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.name();
        let o = self.offset;
        let s = self.size;
        let end = o + s;
        let flag = self.compression_flag;

        write!(f, "{n:13} @ 0x{o:06x}:0x{end:06x} (0x{s:06x}) {flag:032b}")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct CodePartitionDirectory {
    pub header: CPDHeader,
    pub entries: Vec<CPDEntry>,
    pub offset: usize,
    pub name: String,
    pub data: Vec<u8>,
}

// TODO: See https://github.com/skochinsky/me-tools class CPDEntry
// What is the other u8?!
const OFFSET_MASK: u32 = 0xffffff;

impl CodePartitionDirectory {
    pub fn new(data: Vec<u8>, offset: usize) -> Result<Self, String> {
        let header = CPDHeader::read_from_prefix(&data).unwrap();
        let n = header.part_name;
        let name = match std::str::from_utf8(&n) {
            // some names are shorter than 4 bytes and padded with 0x0
            Ok(n) => n.trim_end_matches('\0').to_string(),
            Err(_) => format!("{:02x?}", n),
        };
        let mut entries = Vec::<CPDEntry>::new();
        let header_size = if header.version_or_checksum == 0x00140102 {
            HEADER_SIZE + 4
        } else {
            HEADER_SIZE
        };
        for e in 0..header.entries as usize {
            let pos = header_size + e * 24;
            let mut entry = CPDEntry::read_from_prefix(&data[pos..]).unwrap();
            entry.offset &= OFFSET_MASK;
            entries.push(entry);
        }
        let cpd = CodePartitionDirectory {
            header,
            entries,
            offset,
            name: name.to_string(),
            data,
        };
        Ok(cpd)
    }

    pub fn manifest(&self) -> Result<crate::man::Manifest, String> {
        let entries = &mut self.entries.iter();
        let name = format!("{}.man", self.name);
        if let Some(e) = entries.find(|e| e.name() == name) {
            let b = &self.data[e.offset as usize..];
            crate::man::Manifest::new(b)
        } else {
            Err("no manifest found".to_string())
        }
    }
}
