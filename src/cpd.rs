use serde::{Deserialize, Serialize};
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

pub const CPD_MAGIC: &str = "$CPD";

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
