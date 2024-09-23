use std::io::prelude::*;
use std::{fs::File, str::from_utf8};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeMap;
use zerocopy::FromBytes;
use zerocopy_derive::{FromBytes, FromZeroes};

const PRINT: bool = true;
const DEBUG_FAT: bool = false;
const DUMP_FILES: bool = false;
const VERBOSE: bool = false;

// see https://live.ructf.org/intel_me.pdf slide 35
const PAGE_MAGIC: u32 = 0xaa55_7887;

const PAGE_SIZE: usize = 0x2000;

// NOTE: We cannot use std::mem::size_of::<PageHeader>() here because it is
// larger than the underlying data.
const SLOTS_OFFSET: usize = 18;
// NOTE: System and data pages have different chunk counts and different slot sizes!
const SYS_CHUNKS_OFFSET: usize = SLOTS_OFFSET + 2 * SYS_PAGE_SLOTS;
const DATA_CHUNKS_OFFSET: usize = SLOTS_OFFSET + DATA_PAGE_SLOTS;

const CHUNK_DATA_SIZE: usize = 0x40;
// + 2 bytes checksum
const CHUNK_SIZE: usize = CHUNK_DATA_SIZE + 2;

const SYS_PAGE_CHUNKS: usize = 120;
const SYS_PAGE_SLOTS: usize = SYS_PAGE_CHUNKS + 1;

const DATA_PAGE_CHUNKS: usize = 122;
const DATA_PAGE_SLOTS: usize = DATA_PAGE_CHUNKS;

const SLOT_UNUSED: u16 = 0xffff;
const SLOT_LAST: u16 = 0x7fff;

const VOL_MAGIC: u32 = 0x724F_6201;
// NOTE: We cannot use std::mem::size_of::<VolHeader>() here because it is
// larger than the underlying data.
const VOL_HEADER_SIZE: usize = 14;

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct PageHeader {
    pub magic: [u8; 4],
    // update sequence number
    pub usn: u32,
    pub n_erase: u32,
    pub i_next_erase: u16,
    pub first_chunk: u16, // first chunk index, for data
    pub checksum: u8,
    pub b0: u8, // always 0
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Chunk {
    #[serde(with = "BigArray")]
    pub data: [u8; CHUNK_DATA_SIZE],
    pub crc16: u16,
}

pub type Chunks = BTreeMap<u16, Chunk>;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct SysPage {
    pub offset: usize,
    pub header: PageHeader,
    pub chunks: Chunks,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct DataPage {
    pub offset: usize,
    pub header: PageHeader,
    pub chunks: Chunks,
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct VolHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub chunk_bytes_total: u32,
    pub files: u16,
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
struct DirEntry {
    file_no: u32,
    mode: u16,
    uid: u16,
    gid: u16,
    salt: u16,
    name: [u8; 12],
}

const DIR_ENTRY_SIZE: usize = 24;
// const SZ: usize = std::mem::size_of::<DirEntry>();
// assert_eq!(DIR_ENTRY_SIZE, SZ);

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
struct BlobSec {
    hmac: [u8; 32],
    flags: u32,
    nonce: [u8; 16],
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
*/

// *CCITT CRC-16 is calculated from the chunk data and the 16-bit (2-byte) chunk index
// https://srecord.sourceforge.net/crc16-ccitt.html
const CCITT: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);

fn crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    for (i, e) in table.iter_mut().enumerate() {
        let mut r = i << 8;
        for _ in 0..8 {
            let poly = if r & 0x8000 != 0 { 0x1021 } else { 0 };
            r = (r << 1) ^ poly;
        }
        *e = r as u16;
    }
    table
}

fn crc_idx(v: u16) -> u16 {
    let tab = crc_table();

    let v = [v as u8, (v >> 8) as u8];

    let mut crc: u16 = 0x3fff;
    for b in v {
        let i = (b as u16 ^ (crc >> 8)) as u8 as usize;
        crc = (tab[i] ^ (crc << 8)) & 0x3fff;
    }
    crc
}

fn parse_data_chunks(data: &[u8], first_chunk: u16) -> (Chunks, usize) {
    let mut free_chunks = 0;
    let mut chunks = Chunks::new();

    for chunk_pos in 0..DATA_PAGE_SLOTS {
        let o = SLOTS_OFFSET + chunk_pos;
        let s = u8::read_from_prefix(&data[o..]).unwrap();

        // free chunk
        if s == 0xff {
            free_chunks += 1;
            continue;
        }

        let chunk_index = first_chunk + chunk_pos as u16;

        // Parse the chunk
        let coff = DATA_CHUNKS_OFFSET + chunk_pos * CHUNK_SIZE;
        let cbuf = &data[coff..coff + CHUNK_SIZE];
        let c = Chunk::read_from_prefix(cbuf).unwrap();

        chunks.insert(chunk_index, c);
    }
    (chunks, free_chunks)
}

fn parse_sys_chunks(data: &[u8]) -> (Chunks, usize, usize) {
    let mut dup_chunks = 0;
    let mut free_chunks = 0;
    let mut chunks = Chunks::new();
    let mut chunk_index = 0;

    for chunk_pos in 0..SYS_PAGE_SLOTS {
        let o = SLOTS_OFFSET + 2 * chunk_pos;
        // aka axIdx in PT code
        let slot = u16::read_from_prefix(&data[o..]).unwrap();

        if slot == SLOT_UNUSED {
            free_chunks += 1;
            continue;
        }
        // Last chunk is marked
        if slot == SLOT_LAST {
            let remaining = SYS_PAGE_CHUNKS - chunk_pos;
            free_chunks += remaining;
            break;
        }

        // Parse the chunk
        let coff = SYS_CHUNKS_OFFSET + chunk_pos * CHUNK_SIZE;
        let cbuf = &data[coff..coff + CHUNK_SIZE];
        let c = Chunk::read_from_prefix(cbuf).unwrap();

        // Calculate chunk index
        chunk_index = crc_idx(chunk_index) ^ slot;
        // Calculate chunk checksum
        let mut dd = c.data.clone().to_vec();
        dd.extend_from_slice(&chunk_index.to_le_bytes());
        let cs = CCITT.checksum(&dd);

        assert_eq!(cs, c.crc16);
        // XXX: In reality, chunk index is not unique, so it's not the "index"?
        if chunks.contains_key(&chunk_index) {
            dup_chunks += 1;
            if VERBOSE {
                println!("dup chunk {chunk_pos:03}: {slot:04x} {chunk_index:04x}");
            }
        }
        chunks.insert(chunk_index, c);
    }
    (chunks, free_chunks, dup_chunks)
}

fn get_file<'a>(
    chunks: &Chunks,
    n_sys_chunks: u16,
    fat: &[u16],
    n_files: u16,
    file_index: usize,
) -> Result<Vec<u8>, &'a str> {
    let mut i_node = fat[file_index];
    if VERBOSE {
        println!("  file {file_index:04} iNode {i_node:04x}");
    }
    if i_node == 0xffff {
        return Err("empty file");
    }
    if i_node == 0x0000 {
        return Err("no file");
    }

    let mut data = Vec::<u8>::new();
    loop {
        assert!(i_node >= n_files);
        let ci = i_node + n_sys_chunks - n_files;
        let c = chunks[&ci];
        i_node = fat[i_node as usize];
        // For the last chunk, i_node is the number of remaining bytes
        if i_node > 0 && i_node as usize <= CHUNK_SIZE {
            data.extend_from_slice(&c.data[..i_node as usize]);
            break;
        }
        data.extend_from_slice(&c.data);
    }
    Ok(data)
}

fn dump_u16(a: &[u16]) {
    println!();
    for (i, b) in a.iter().enumerate() {
        if i % 64 == 0 {
            println!();
        }
        if i % 16 == 0 {
            print!("\n{i:04x}: ");
        }
        print!("{b:04x} ");
    }
    println!();
    println!();
}

// Dump some example files.
fn dump_files(chunks: &Chunks, n_sys_chunks: u16, fat: &[u16], n_files: u16) {
    let files: Vec<(usize, &str)> = [(6, "intel.cfg"), (7, "fitc.cfg")].into();
    for (file_index, file_name) in files {
        match get_file(chunks, n_sys_chunks, fat, n_files, file_index) {
            Ok(f) => {
                println!("file {file_index:04} {file_name}: {:5} bytes", f.len());
                let mut file = File::create(file_name).unwrap();
                file.write_all(&f).unwrap();
            }
            Err(e) => {
                println!("file {file_index:04} {file_name}: {e}");
            }
        }
    }
}

fn print_files(chunks: &Chunks, n_sys_chunks: u16, fat: &[u16], n_files: u16) {
    println!(" files: {n_files}");
    for file_index in 0..n_files as usize {
        match get_file(chunks, n_sys_chunks, fat, n_files, file_index) {
            Ok(f) => {
                println!("    {file_index:04}: {:5} bytes", f.len());
            }
            Err(e) => {
                println!("    {file_index:04}: {e}");
            }
        }
    }
}

const VFS_INTEGRITY: u16 = 0x0200;
const VFS_ENCRYPTION: u16 = 0x0400;
const VFS_ANTI_REPLAY: u16 = 0x0800;
const VFS_NONINTEL: u16 = 0x2000;
const VFS_DIRECTORY: u16 = 0x4000;

const FILE_TYPE_XXX: u16 = 0;
const FILE_TYPE_DIR: u16 = 1;

const SEC_SIZE: usize = 32 + 4 + 16;

fn get_blob<'a>(
    chunks: &Chunks,
    n_sys_chunks: u16,
    fat: &[u16],
    n_files: u16,
    dir: &str,
    file_index: usize,
) -> Result<Vec<u8>, &'a str> {
    let salt = 0;
    let mode = VFS_INTEGRITY | VFS_NONINTEL;
    // TODO: Why & 0xfff ?
    let fi = file_index & 0xfff;
    let file_data = get_file(chunks, n_sys_chunks, fat, n_files, fi).unwrap();
    let file_type = FILE_TYPE_DIR;

    let size = file_data.len();
    let list_size = size - SEC_SIZE;
    let rest = list_size % DIR_ENTRY_SIZE;
    assert_eq!(rest, 0);

    let sec = BlobSec::read_from_prefix(&file_data[list_size..]).unwrap();
    assert_eq!(sec.flags, 0x98);

    let mut files = Vec::<DirEntry>::new();
    for o in (0..list_size).step_by(DIR_ENTRY_SIZE) {
        let d = &file_data[o..o + DIR_ENTRY_SIZE];
        let e = DirEntry::read_from_prefix(d).unwrap();
        files.push(e);
    }

    for (i, f) in files.iter().enumerate() {
        let m = f.mode;
        let fno = f.file_no;
        let fi = fno & 0xfff;
        let n = &f.name[..2];
        if let Ok(n) = from_utf8(n) {
            let n = n.split("\0").collect::<Vec<&str>>()[0];
            if n == "." || n == ".." {
                print!("  |  {fi:04} {n:12} {m:04x}");
                continue;
            }
        }
        if let Ok(n) = from_utf8(&f.name) {
            if i % 3 == 0 {
                println!("  |");
            }
            let n = n.split("\0").collect::<Vec<&str>>()[0];
            print!("  |  {fi:04x} {n:12} {m:04x}");
        }
    }
    println!("  |");

    for (i, f) in files.iter().enumerate() {
        let n = &f.name[..2];
        if let Ok(n) = from_utf8(n) {
            let n = n.split("\0").collect::<Vec<&str>>()[0];
            if n == "." || n == ".." {
                continue;
            }
        }
        if let Ok(n) = from_utf8(&f.name) {
            let n = n.split("\0").collect::<Vec<&str>>()[0];
            if !n.is_empty() && f.mode & VFS_DIRECTORY > 0 {
                println!();
                let fi = f.file_no as usize;
                let nd = format!("{dir}/{n}");
                get_dir(chunks, n_sys_chunks, fat, n_files, &nd, fi);
            }
        }
    }

    Ok(Vec::<u8>::new())
}

fn get_dir(
    chunks: &Chunks,
    n_sys_chunks: u16,
    fat: &[u16],
    n_files: u16,
    dir: &str,
    file_index: usize,
) {
    println!("/{dir}:");
    match get_blob(chunks, n_sys_chunks, fat, n_files, dir, file_index) {
        Ok(_) => {}
        Err(e) => {
            println!("{e}");
        }
    }
}

pub fn parse(data: &[u8]) {
    let size = data.len();
    let n_pages = size / PAGE_SIZE;
    let n_sys_pages = n_pages / 12;
    let n_data_pages = n_pages - n_sys_pages - 1;
    let n_data_chunks = n_data_pages * DATA_PAGE_CHUNKS;

    // Parse the pages and chunks.
    let mut data_pages = Vec::<DataPage>::new();
    let mut sys_pages = Vec::<SysPage>::new();
    let mut blank_page = 0;

    for pos in (0..size).step_by(PAGE_SIZE) {
        let slice = &data[pos..pos + PAGE_SIZE];
        if u32::read_from_prefix(slice).unwrap() == PAGE_MAGIC {
            let header = PageHeader::read_from_prefix(slice).unwrap();
            // The first chunk tells other whether it's a data or system page.
            let fc = header.first_chunk;
            let is_data = fc > 0;
            if is_data {
                let (chunks, free) = parse_data_chunks(slice, fc);
                let l = chunks.len();
                if VERBOSE {
                    println!("data page @ 0x{pos:06x}: first chunk {fc:04x?}",);
                    println!("  {l} chunks, {free} free");
                }
                data_pages.push(DataPage {
                    offset: pos,
                    header,
                    chunks,
                });
            } else {
                let (chunks, free, dups) = parse_sys_chunks(slice);
                let l = chunks.len();
                if VERBOSE {
                    println!("sys page @ 0x{pos:06x}: usn {:02x?}", header.usn);
                    println!("  {l} chunks, {dups} duplicates, {free} free");
                }
                sys_pages.push(SysPage {
                    offset: pos,
                    header,
                    chunks,
                });
            }
        } else {
            // this should occur exactly once
            assert_eq!(blank_page, 0);
            blank_page = pos;
        }
    }
    // sort by Update Sequence Number
    sys_pages.sort_by_key(|p| p.header.usn);
    data_pages.sort_by_key(|p| p.header.first_chunk);

    // NOTE: The chunks have indices and are not sorted upfront.
    // The first data chunk index must be less than the last system chunk.
    let n_sys_chunks = data_pages.first().unwrap().header.first_chunk;

    let mut chunks = Chunks::new();
    for p in sys_pages {
        for (i, c) in p.chunks {
            assert!(i < n_sys_chunks);
            chunks.insert(i, c);
        }
    }
    for (pi, p) in data_pages.iter().enumerate() {
        let first_chunk_expected = n_sys_chunks as usize + pi * DATA_PAGE_CHUNKS;
        assert_eq!(p.header.first_chunk as usize, first_chunk_expected);
        for (ci, c) in &p.chunks {
            // duplicates are not allowed
            assert!(!chunks.contains_key(ci));
            chunks.insert(*ci, *c);
        }
    }

    // The first chunk is the start of the volume, so check magic at beginning.
    let c0 = chunks[&0].data;
    let magic = u32::read_from_prefix(&c0).unwrap();
    assert_eq!(magic, VOL_MAGIC);
    let vh = VolHeader::read_from_prefix(&c0).unwrap();

    // NOTE: Not all system chunks are really set.
    // Initialize a zero-filled slice and fill in the existing chunks.
    let n_sys_bytes = n_sys_chunks as usize * CHUNK_DATA_SIZE;
    let mut sys_data = vec![0u8; n_sys_bytes];
    for i in 0..n_sys_chunks {
        if chunks.contains_key(&i) {
            let c = chunks.get(&i).unwrap();
            let o = i as usize * CHUNK_DATA_SIZE;
            // FIXME: This could probably be more efficient.
            for (j, b) in c.data.iter().enumerate() {
                sys_data[o + j] = *b;
            }
        }
    }

    // NOTE: The file system table comes right after the volume header.
    // Table entries are two bytes each.
    let total_files_and_chunks = vh.files as usize + n_data_chunks;
    let mut fat = vec![0u16; total_files_and_chunks];
    let d = &sys_data[VOL_HEADER_SIZE..VOL_HEADER_SIZE + total_files_and_chunks * 2];
    for (i, e) in fat.iter_mut().enumerate() {
        let p = i * 2;
        *e = u16::read_from(&d[p..p + 2]).unwrap();
    }
    if DEBUG_FAT {
        println!("fat size: {}", fat.len());
        dump_u16(&fat);
    }

    if PRINT {
        let n_data_bytes = n_data_chunks * CHUNK_DATA_SIZE;
        let n_total_bytes = n_sys_bytes + n_data_bytes;
        println!();
        println!("MFS");
        println!(" - size: {size}");
        println!(" - pages: {n_pages}");
        println!("    system: {n_sys_pages}");
        println!("      data: {n_data_pages}");
        println!("    blank at 0x{blank_page:08x}");
        println!(" - chunks: {}", chunks.len());
        println!("    system: {n_sys_chunks}");
        println!("      data: {n_data_chunks}");
        println!(" - total files and data chunks: {total_files_and_chunks}");
        println!(" - chunk bytes: {n_total_bytes}");
        println!("    system: {n_sys_bytes}");
        println!("      data: {n_data_bytes}");
        println!();
        print_files(&chunks, n_sys_chunks, &fat, vh.files);
    }

    if DUMP_FILES {
        dump_files(&chunks, n_sys_chunks, &fat, vh.files);
    }

    // TODO: traverse directories
    if fat[8] != 0x0000 {
        println!("var fs:");
        get_dir(&chunks, n_sys_chunks, &fat, vh.files, "home", 0x10000008);
    }
}
