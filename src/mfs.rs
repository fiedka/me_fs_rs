use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zerocopy_derive::{FromBytes, FromZeroes};

// see https://live.ructf.org/intel_me.pdf slide 35
pub const MFS_MAGIC: u32 = 0xaa55_7887;

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct MFSPageHeader {
    pub magic: [u8; 4],
    // update sequence number
    pub usn: u32,
    pub n_erase: u32,
    pub i_next_erase: u16,
    pub first_chunk: u16, // first chunk index, for data
    pub checksum: u8,
    pub b0: u8, // always 0
}

use std::collections::BTreeMap;

pub type Chunks = BTreeMap<u16, MFSChunk>;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct MFSSysPage {
    pub offset: usize,
    pub header: MFSPageHeader,
    pub chunks: Chunks,
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct MFSDataPage {
    pub offset: usize,
    pub header: MFSPageHeader,
    #[serde(with = "BigArray")]
    pub a_free: [u8; MFS_DATA_PAGE_SLOTS],
}

// XXX: this yields 20... why?
pub const MFS_PAGE_HEADER_SIZE: usize = std::mem::size_of::<MFSPageHeader>();

pub const MFS_PAGE_SIZE: usize = 0x2000;
pub const MFS_CHUNK_DATA_SIZE: usize = 0x40;
// + 2 bytes checksum
pub const MFS_CHUNK_SIZE: usize = MFS_CHUNK_DATA_SIZE + 2;

pub const MFS_SYS_PAGE_CHUNKS: usize = 120;
pub const MFS_SYS_PAGE_SLOTS: usize = MFS_SYS_PAGE_CHUNKS + 1;

pub const MFS_DATA_PAGE_CHUNKS: usize = 122;
pub const MFS_DATA_PAGE_SLOTS: usize = MFS_DATA_PAGE_CHUNKS;

pub const MFS_SLOT_UNUSED: u16 = 0xffff;
pub const MFS_SLOT_LAST: u16 = 0x7fff;

pub const XXX_MAGIC: u32 = 0x724F_6201;

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct MFSChunk {
    #[serde(with = "BigArray")]
    pub data: [u8; MFS_CHUNK_DATA_SIZE],
    pub crc16: u16,
}

/*
data areas

Iterate over all data pages
  nSysChunks = min(nSysPages, pg.hdr.firstChunk)
    Iterate over all used chunks on the current page
      dataChunks[pg.hdr.firstChunk + i] = pg.chunks[i].data

system area

Iterate over system pages in ascending USN order
  Iterate over all used chunks on the current page
    Calculate chunk size (iChunk) based on pg.axIdx[i]
    sysArea[iChunk*64 : (iChunk+1)*64] = pg.chunks[i].data

found in sys page:

000e86b0: 0162 4f72 0100 0000 808b 0500 0002 0000  .bOr............
000e86c0: 0000 fd0e f80e 1215 780a 0002 0000 ce14  ........x.......

cbTotal = 0x00058b08 = 363272
nFiles = 0x200 = 512

typedef struct {
    unsigned __int32 sign; // Сигнатура тома == 0x724F6201
    unsigned __int32 ver; // Версия тома? == 1
    unsigned __int32 cbTotal; // Общая емкость тома (системная область + данные)
    unsigned __int16 nFiles; // Число файловых записей
} T_MFS_Volume_Hdr; // 14 bytes

typedef struct {
    T_MFS_Volume_Hdr vol; // Заголовок тома
    unsigned __int16 aFAT[vol.nFiles + nDataChunks]; // Таблица размещения файлов
} T_MFS_System_Area;
*/
