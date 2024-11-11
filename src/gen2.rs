use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

const ENTRY_MAGIC: &[u8] = b"$MME";

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Entry {
    magic: [u8; 4],
    name: [u8; 16],
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
    header: Header,
    entries: Vec<Entry>,
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
