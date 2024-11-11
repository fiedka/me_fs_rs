use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};
use std::str::from_utf8;
use zerocopy::{FromBytes, Ref};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

const ENTRY_MAGIC: &[u8] = b"$MME";

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Entry {
    pub magic: [u8; 4],
    pub name: [u8; 0x10],
    pub _14: [u8; 0x20],
    pub _34: u32, // e.g. 0x0200_9000
    pub _38: u32, // e.g. 0x0001_5b4a
    pub _3c: u32, // e.g. 0x0004_2000
    pub _40: u32, // e.g. 0x0001_d13b
    pub _44: u32, // e.g. 0x0004_b425
    pub _48: u32, // e.g. 0x0004_b425 (often same as _44!)
    pub _4c: u32, // e.g. 0x2009_1000
    pub _50: u32, // e.g. 0x0010_d42a
    pub _54: u32, // e.g. 0x0000_0008
    pub _58: u32, // so far all 0
    pub _5c: u32, // so far all 0
}

impl Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match from_utf8(&self.name) {
            Ok(n) => write!(f, "{n}"),
            Err(_) => write!(f, "{:02x?}", self.name),
        }
    }
}

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Header {
    checksum: [u8; 4],
    name: [u8; 4],
    _pad: [u8; 8],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct Directory {
    pub header: Header,
    pub entries: Vec<Entry>,
}

const HEADER_SIZE: usize = core::mem::size_of::<Header>();

impl Directory {
    pub fn new(data: &[u8], count: usize) -> Result<Self, String> {
        let Some(header) = Header::read_from_prefix(data) else {
            return Err("cannot parse ME FW Gen 2 directory header".to_string());
        };
        let pos = HEADER_SIZE;
        let slice = &data[pos..];
        let Some((r, _)) = Ref::<_, [Entry]>::new_slice_from_prefix(slice, count) else {
            return Err(format!(
                "cannot parse ME FW Gen 2 directory entries @ {:08x}",
                pos
            ));
        };
        let entries = r.into_slice().to_vec();
        Ok(Self { header, entries })
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
