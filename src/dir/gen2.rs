use crate::dir::man::{self, Manifest};
use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};
use std::str::from_utf8;
use zerocopy::{FromBytes, Ref};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

const ENTRY_MAGIC: &[u8] = b"$MME";
const SIG_LUT: u32 = u32::from_le_bytes(*b"LLUT");
const SIG_LZMA: u32 = u32::from_le_bytes([0x36, 0x00, 0x40, 0x00]);

// https://github.com/skochinsky/me-tools me_unpack.py MeModuleHeader2
#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Entry {
    pub magic: [u8; 4],
    pub name: [u8; 0x10],
    pub hash: [u8; 0x20],
    pub mod_base: u32,     // e.g. 0x0200_9000
    pub offset: u32,       // e.g. 0x0001_5b4a
    pub code_size: u32,    // e.g. 0x0004_2000
    pub size: u32,         // e.g. 0x0001_d13b
    pub memory_size: u32,  // e.g. 0x0004_b425
    pub pre_uma_size: u32, // e.g. 0x0004_b425 (often same as memory_size)
    pub entry_point: u32,  // e.g. 0x2009_1000
    pub flags: u32,        // e.g. 0x0010_d42a
    pub _54: u32,          // e.g. 0x0000_0008
    pub _58: u32,          // so far all 0
    pub _5c: u32,          // so far all 0
}

#[derive(Clone, Copy, Debug)]
pub enum Compression {
    Uncompressed,
    Huffman,
    Lzma,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub struct BinaryMap {
    pub rapi: u32, // 3 bits, really
    pub kapi: u32, // 2 bits, really
    pub code_start: usize,
    pub code_end: usize,
    pub data_end: usize,
}

impl Entry {
    pub fn compression_type(&self) -> Compression {
        let comp_flag = (self.flags >> 4) & 0b111;
        match comp_flag {
            0 => Compression::Uncompressed,
            1 => Compression::Huffman,
            2 => Compression::Lzma,
            _ => Compression::Unknown,
        }
    }

    pub fn bin_map(&self) -> BinaryMap {
        let b = self.mod_base;
        let f = self.flags;
        let rapi = (f >> 17) & 0b111;
        let kapi = (f >> 20) & 0b11;
        let code_start = (b + (rapi + kapi) * 0x1000) as usize;
        let code_end = (b + self.code_size) as usize;
        let data_end = (b + self.memory_size) as usize;
        BinaryMap {
            rapi,
            kapi,
            code_start,
            code_end,
            data_end,
        }
    }
}

impl Display for BinaryMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = self.rapi;
        let k = self.kapi;
        let s = self.code_start;
        let e = self.code_end;
        let de = self.data_end;
        write!(
            f,
            "RAPI {r:03b} KAPI {k:02b} code {s:08x}:{e:08x}, data end {de:08x}"
        )
    }
}

impl Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match from_utf8(&self.name) {
            Ok(n) => n.trim_end_matches('\0').to_string(),
            Err(_) => format!("{:02x?}", self.name),
        };
        let o = self.offset;
        let s = self.size;
        let e = self.entry_point;
        write!(f, "{n:16} {s:08x} @ {o:08x}, entry point {e:08x}")
    }
}

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Header {
    name: [u8; 4],
    _pad: [u8; 8],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct Directory {
    pub manifest: Manifest,
    pub header: Header,
    pub entries: Vec<Entry>,
    pub offset: usize,
    pub name: String,
}

impl Display for Directory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = &self.name;
        let o = self.offset;
        let m = self.manifest;
        write!(f, "{n} @ {o:08x}, {m}")
    }
}

const HEADER_SIZE: usize = core::mem::size_of::<Header>();

impl Directory {
    pub fn new(data: &[u8], offset: usize) -> Result<Self, String> {
        let Ok(manifest) = Manifest::new(data) else {
            return Err("cannot parse Gen 2 directory manifest".to_string());
        };
        let count = manifest.header.entries as usize;
        let d = &data[man::MANIFEST_SIZE..];
        let Some(header) = Header::read_from_prefix(d) else {
            return Err("cannot parse ME FW Gen 2 directory header".to_string());
        };
        let pos = man::MANIFEST_SIZE + HEADER_SIZE;
        let slice = &data[pos..];
        let Some((r, _)) = Ref::<_, [Entry]>::new_slice_from_prefix(slice, count) else {
            return Err(format!(
                "cannot parse ME FW Gen 2 directory entries @ {:08x}",
                pos
            ));
        };
        let entries = r.into_slice().to_vec();
        let name = match from_utf8(&header.name) {
            Ok(n) => n.trim_end_matches('\0').to_string(),
            Err(_) => format!("{:02x?}", header.name),
        };
        Ok(Self {
            manifest,
            header,
            entries,
            offset,
            name,
        })
    }
}

/*
00147280: e7b0 f3a1 4d44 4d56 0000 0000 0000 0000  ....MDMV........

00147290: 244d 4d45 5061 7670 0000 0000 0000 0000  $MMEPavp........
001472a0: 0000 0000 f77e 0ea3 2425 76eb 943f b376  .....~..$%v..?.v
001472b0: bcb1 d497 84e0 e299 fd9d edb5 41d4 756d  ............A.um
001472c0: 230e aa7e 0000 0420 f403 0000 0090 0200  #..~... ........
001472d0: 5657 0100 b8f9 0400 b8f9 0400 0010 0420  VW.............
001472e0: aad4 1000 0700 0000 0000 0000 0000 0000  ................

001472f0: 244d 4d45 4a4f 4d00 0000 0000 0000 0000  $MMEJOM.........
00147300: 0000 0000 2fa2 d85d 3ef0 e566 cee4 2be7  ..../..]>..f..+.
00147310: 5991 7141 e7dc 6e90 2f45 c01b 113a c34e  Y.qA..n./E...:.N
00147320: bdc9 8df2 0000 0920 4a5b 0100 0020 0400  ....... J[... ..
00147330: 3bd1 0100 b425 0400 b425 0400 0010 0920  ;....%...%.....
00147340: 2ad4 1000 0800 0000 0000 0000 0000 0000  *...............
*/
