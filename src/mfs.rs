use core::fmt::{self, Display};
use core::mem::size_of;
use std::fs::{create_dir_all, File};
use std::io::prelude::*;
use std::path::Path;
use std::str::from_utf8;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::{BTreeMap, HashSet};
use zerocopy::FromBytes;
use zerocopy_derive::{FromBytes, FromZeroes};

const PRINT: bool = true;
const DUMP_FILES: bool = false;

const DEBUG_FAT: bool = true;
const VERBOSE: bool = true;

// see https://live.ructf.org/intel_me.pdf slide 35
// https://www.blackhat.com/docs/eu-17/materials/eu-17-Sklyarov-Intel-ME-Flash-File-System-Explained.pdf
const GEN3_PAGE_MAGIC: u32 = 0xaa55_7887;
const GEN3_PAGE_SIZE: usize = 0x2000;

// also V8 and V9...
const GEN2_PAGE_MAGIC_MASK: u32 = 0xfff0_7800;
const GEN2_PAGE_SIZE: usize = 0x4000;

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
const VOL_HEADER_SIZE: usize = size_of::<VolHeader>();

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
#[repr(C, packed)]
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

impl DirEntry {
    pub fn is_dir(&self) -> bool {
        self.mode & VFS_DIRECTORY > 0
    }
}

const DIR_ENTRY_SIZE: usize = 24;

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
struct BlobSec {
    hmac: [u8; 32],
    flags: u32,
    nonce: [u8; 16],
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
struct RndCtr {
    random: u32,
    counter: u32,
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

fn parse_sys_chunks(data: &[u8]) -> Result<(Chunks, usize, usize), String> {
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

        if cs != c.crc16 {
            return Err(format!(
                "chunk {chunk_pos} checksum {cs:04x} does not match expected checksum {:04x}",
                c.crc16
            ));
        }
        // XXX: In reality, chunk index is not unique, so it's not the "index"?
        if chunks.contains_key(&chunk_index) {
            dup_chunks += 1;
            if VERBOSE {
                println!("dup chunk {chunk_pos:03}: {slot:04x} {chunk_index:04x}");
            }
        }
        chunks.insert(chunk_index, c);
    }
    Ok((chunks, free_chunks, dup_chunks))
}

const FILE_NONE: u16 = 0x0000;
const FILE_EMPTY: u16 = 0xffff;

fn is_inode_active(inode: u16) -> bool {
    inode != FILE_NONE && inode != FILE_EMPTY
}

fn get_file(
    chunks: &Chunks,
    n_sys_chunks: u16,
    fat: &[u16],
    n_files: u16,
    file_index: u32,
) -> Result<Vec<u8>, String> {
    let mut i_node = fat[file_index as usize];
    if VERBOSE && is_inode_active(i_node) {
        println!("  file {file_index:04} iNode {i_node:04x}");
    }
    if i_node == FILE_EMPTY {
        return Err("empty".to_string());
    }
    if i_node == FILE_NONE {
        return Err("no file".to_string());
    }

    let mut data = Vec::<u8>::new();
    loop {
        if i_node < n_files {
            return Err(format!("inode {i_node} less than file count {n_files}"));
        }
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
        match get_file(chunks, n_sys_chunks, fat, n_files, file_index as u32) {
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
    for file_index in 0..n_files as u32 {
        match get_file(chunks, n_sys_chunks, fat, n_files, file_index) {
            Ok(f) => {
                println!("    {file_index:04}: {:5} bytes", f.len());
                let l_size = f.len() - SEC_SIZE;
                if l_size % DIR_ENTRY_SIZE == 0 {
                    println!("  may be a dir");
                }
            }
            Err(e) => {
                println!("    {file_index:04}: {e}");
            }
        }
    }
}

const VFS_INTEGRITY: u16 = 0x0200;
// const VFS_ENCRYPTION: u16 = 0x0400;
// const VFS_ANTI_REPLAY: u16 = 0x0800;
const VFS_NONINTEL: u16 = 0x2000;
const VFS_DIRECTORY: u16 = 0x4000;

const SEC_SIZE: usize = 32 + 4 + 16;

const OLD_FLAGS: u32 = 0x90;
// const NEW_FLAGS: u32 = 0x98;

// TODO: use crate for bits
// XXX: ThinkPad X270 and T480 match NEW_FLAGS, ASRock Z170M matches OLD_FLAGS.
fn check_dir_sec(sec: &BlobSec) -> Result<(), String> {
    let expected_flags = OLD_FLAGS;
    if false {
        let flags = sec.flags;
        if flags != expected_flags {
            return Err(format!(
                "flags {flags:032b} do not match {expected_flags:032b}"
            ));
        }
    }
    let ar = sec.flags & 0b11;
    let enc = (sec.flags >> 2) & 1;
    // let i_ar = (sec.flags >> 10) & 0x3ff;

    // NOTE: This is 7 unknown bits; what do they mean?
    // XXX: The lowest bit isn't set in PT's Python implementation.
    // See OLD_FLAGS vs NEW_FLAGS.
    let u7 = (sec.flags >> 3) & 0x7f;
    let expected_u7 = expected_flags >> 3;
    // XXX: equivalent to first check
    if u7 != expected_u7 {
        // return Err(format!("flags 3..10 {u7:b} not matching {expected_u7:b}"));
    }
    // NOTE: This is 12 unknown bits.
    let u12 = sec.flags >> 20;
    if u12 != enc << 1 {
        return Err(format!("flags 20..31 {u12:b} not matching {enc:b}"));
    }

    // I haven't seen this yet.
    if ar > 0 {
        let rnd_ctr = RndCtr::read_from_prefix(&sec.nonce);
        println!("{rnd_ctr:#?}");
    }

    // I haven't seen this yet.
    if enc > 0 {
        println!("ENCRYPTED");
    }

    if ar == 0 && enc == 0 {
        let nonce = sec.nonce;
        if !nonce.eq(&[0u8; 16]) {
            return Err(format!("nonce {nonce:04x?} not all zero"));
        }
    }

    Ok(())
}

// TODO: Why 0xfff ?
const FILE_INDEX_MASK: u32 = 0xfff;

const FALLBACK_WALK_BROKEN_DIR: bool = false;

fn get_blob(
    chunks: &Chunks,
    n_sys_chunks: u16,
    fat: &[u16],
    n_files: u16,
    path: &Path,
    file_index: u32,
) -> Result<Vec<u8>, String> {
    // TODO
    // let salt = 0;
    // TODO: Needs to be passed.
    let mode = VFS_INTEGRITY | VFS_NONINTEL;
    let fi = file_index & FILE_INDEX_MASK;
    let file_data = get_file(chunks, n_sys_chunks, fat, n_files, fi)?;

    // must be n * DIR_ENTRY_SIZE + SEC_SIZE
    let size = file_data.len();
    let list_size = size - SEC_SIZE; // 72
    let rest = list_size % DIR_ENTRY_SIZE;
    if rest != 0 {
        println!("{size} {:#02x?}", &file_data[..24]);
        return Err(format!(
            "directory listing for file {fi} has leftover bytes"
        ));
    }

    if mode & VFS_INTEGRITY > 0 {
        let sec = BlobSec::read_from_prefix(&file_data[list_size..]).unwrap();
        check_dir_sec(&sec)?;
    }

    let mut files = Vec::<DirEntry>::new();
    for o in (0..list_size).step_by(DIR_ENTRY_SIZE) {
        let d = &file_data[o..o + DIR_ENTRY_SIZE];
        let e = DirEntry::read_from_prefix(d).unwrap();
        files.push(e);
    }

    for (i, f) in files.iter().enumerate() {
        let m = f.mode;
        let fno = f.file_no;
        let fi = fno & FILE_INDEX_MASK;
        let ft = if f.mode & VFS_DIRECTORY > 0 { "d" } else { "f" };
        let n = &f.name[..2];
        if PRINT && i % 3 == 0 {
            println!("  |");
        }
        if let Ok(n) = from_utf8(n) {
            let n = n.split("\0").collect::<Vec<&str>>()[0];
            if n == "." || n == ".." {
                if PRINT {
                    print!("  |  {fi:04} {n:12} {m:04x} {ft}");
                }
                continue;
            }
        }
        if PRINT {
            if let Ok(n) = from_utf8(&f.name) {
                let n = n.split("\0").collect::<Vec<&str>>()[0];
                print!("  |  {fi:04} {n:12} {m:04x} {ft}");
            } else {
                print!("  |  {fi:04} [>unknown<]  {m:04x} {ft}");
            }
        }
    }
    if PRINT {
        println!("  |");
    }

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
            let fi = f.file_no & FILE_INDEX_MASK;
            let next_path = path.join(Path::new(n));
            if f.is_dir() {
                if PRINT {
                    println!();
                }
                walk_dir(chunks, n_sys_chunks, fat, n_files, &next_path, fi);
            } else if DUMP_FILES {
                create_dir_all(path).unwrap();
                let mut file = File::create(next_path).unwrap();
                let d = get_file(chunks, n_sys_chunks, fat, n_files, fi)?;
                file.write_all(&d).unwrap();
            }
        } else {
            let fi = f.file_no & FILE_INDEX_MASK;
            let i_node = fat[fi as usize];
            let next_path = path.join(Path::new("xxx"));
            if FALLBACK_WALK_BROKEN_DIR && f.is_dir() && is_inode_active(i_node) {
                walk_dir(chunks, n_sys_chunks, fat, n_files, &next_path, fi);
            } else {
                println!("NOT A VALID DIR");
            }
        }
    }

    Ok(Vec::<u8>::new())
}

// TODO: expose error once we figure things out...
fn walk_dir(
    chunks: &Chunks,
    n_sys_chunks: u16,
    fat: &[u16],
    n_files: u16,
    path: &Path,
    file_index: u32,
) {
    if PRINT {
        println!("/{}:", path.display());
    }
    match get_blob(chunks, n_sys_chunks, fat, n_files, path, file_index) {
        Ok(_) => {}
        Err(e) => {
            println!("{e}");
        }
    }
}

fn parse_gen3(data: &[u8]) -> Result<bool, String> {
    let size = data.len();
    println!("Trying to parse MFS for Gen 3, size: {size:08x}");

    let n_pages = size / GEN3_PAGE_SIZE;
    let n_sys_pages = n_pages / 12;
    let n_data_pages = n_pages - n_sys_pages - 1;
    let n_data_chunks = n_data_pages * DATA_PAGE_CHUNKS;

    // Parse the pages and chunks.
    let mut data_pages = Vec::<DataPage>::new();
    let mut sys_pages = Vec::<SysPage>::new();
    let mut blank_page = 0;

    for pos in (0..size).step_by(GEN3_PAGE_SIZE) {
        let slice = &data[pos..pos + GEN3_PAGE_SIZE];
        if u32::read_from_prefix(slice).unwrap() == GEN3_PAGE_MAGIC {
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
                let (chunks, free, dups) = parse_sys_chunks(slice)?;
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
            if blank_page != 0 {
                return Err("more than one blank page found".to_string());
            };
            blank_page = pos;
        }
    }
    // sort by Update Sequence Number
    sys_pages.sort_by_key(|p| p.header.usn);
    data_pages.sort_by_key(|p| p.header.first_chunk);

    // NOTE: The chunks have indices and are not sorted upfront.
    // The first data chunk index must be less than the last system chunk.
    let first_page = data_pages.first().ok_or("no data pages")?;
    let n_sys_chunks = first_page.header.first_chunk;

    let mut chunks = Chunks::new();
    for p in sys_pages {
        for (i, c) in p.chunks {
            if i >= n_sys_chunks {
                return Err(format!(
                    "system chunk {i} outside its boundary {n_sys_chunks}",
                ));
            }
            chunks.insert(i, c);
        }
    }
    for (pi, p) in data_pages.iter().enumerate() {
        let first_chunk_expected = n_sys_chunks as usize + pi * DATA_PAGE_CHUNKS;
        let fc = p.header.first_chunk as usize;
        if fc != first_chunk_expected {
            return Err(format!(
                "first chunk ID in data page {pi} is {fc}, expected {first_chunk_expected}",
            ));
        }
        for (ci, c) in &p.chunks {
            // duplicates are not allowed
            if chunks.contains_key(ci) {
                return Err(format!(
                    "duplicate chunk ID {ci} encountered in data page {pi}"
                ));
            }
            chunks.insert(*ci, *c);
        }
    }

    // The first chunk is the start of the volume, so check magic at beginning.
    let c0 = chunks[&0].data;
    let magic = u32::read_from_prefix(&c0).unwrap();
    if magic != VOL_MAGIC {
        return Err(format!(
            "first bytes of volume {magic:08x} do not match magic {VOL_MAGIC:08x}"
        ));
    }
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
        if VERBOSE {
            print_files(&chunks, n_sys_chunks, &fat, vh.files);
        }
    }

    if DUMP_FILES {
        dump_files(&chunks, n_sys_chunks, &fat, vh.files);
    }

    // traverse directories
    if fat[8] != FILE_NONE {
        if PRINT {
            println!("var fs:");
        }
        let home_dir = Path::new("home");
        if true {
            walk_dir(&chunks, n_sys_chunks, &fat, vh.files, home_dir, 0x10000008);
        }
        if false {
            // XXX: has files `ntid3` (data) and `uncfg` (empty)
            walk_dir(&chunks, n_sys_chunks, &fat, vh.files, home_dir, 114);
            // XXX: `PttProf` (data), `eyCache4wP` (dir), `RsaKeyCache5` (empty)
            // Should likely be RsaKeyCache1,2,3,4,5,6,7,8,9,10
            walk_dir(&chunks, n_sys_chunks, &fat, vh.files, home_dir, 133);
            // XXX: _k_m0 (dir), widi_k_m1 (file), widi_k_m7 (file), wv_keybox
            walk_dir(&chunks, n_sys_chunks, &fat, vh.files, home_dir, 81);
            // XXX: sec_touch (empty)
            walk_dir(&chunks, n_sys_chunks, &fat, vh.files, home_dir, 53);
        }
        if false {
            walk_dir(&chunks, n_sys_chunks, &fat, vh.files, home_dir, 28);
        }
    }
    Ok(true)
}

const GEN2_MAGIC: u32 = u32::from_le_bytes(*b"MFS\0");

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Gen2PageHeader {
    pub page_num: u8,
    pub _1: u8, // ff
    pub page_flag: u8,
    pub _3: u8, // ff
    pub all_0: u32,
    pub magic: [u8; 4], // first page only, ffff otherwise
    pub smth: u32,      // first page only, ffff otherwise
    pub all_f: u32,
}

impl Display for Gen2PageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let num = self.page_num;
        let flag = self.page_flag;
        if num == 0xff && flag == 0xff {
            return write!(f, "page unused");
        }
        write!(f, "page {num:02}, flag {flag:08b}")
    }
}

const GEN2_PAGE_HEADER_SIZE: usize = size_of::<Gen2PageHeader>();

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct Gen2Page {
    pub header: Gen2PageHeader,
    // pub indices: Gen2Indices,
    pub chunks: Vec<Gen2Chunk>,
    pub offset: usize,
}

impl Gen2Page {
    pub fn is_active(&self) -> bool {
        let n = self.header.page_num;
        n != 0x00 && n != 0xff
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Gen2ChunkHeader {
    pub flags: u8,
    pub size: u8,
}

impl Display for Gen2ChunkHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fl = self.flags;
        // looks like the first bits are _always_ `10`.
        let f0 = (fl >> 4) & 0b11;
        let f1 = fl & 0b1111;
        let sz = self.size;
        let fb = match f1 {
            0b0000 => "  A ".to_string(),
            _ => format!("{f1:04b}"),
        };
        let id = fl & 0b111111;
        write!(f, "{id:02x} {f0:02b} {fb} {sz:3}")
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Gen2Chunk {
    pub header: Gen2ChunkHeader,
    pub offset: usize,
}

impl Display for Gen2Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = self.header;
        // TODO: offset
        write!(f, "{h}")
    }
}

impl Gen2Chunk {
    pub fn is_active(&self) -> bool {
        self.header.flags & 0b1111 == 0
    }
}

#[derive(FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Gen2PageSmth {
    pub _0: u16,
    pub id: u8,
    pub _3: u16,
    pub _5: u16,
    pub _7: u16,
    pub _9: u16,
}

impl Display for Gen2PageSmth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // apparently, some special values occur frequently
        let t = self._0;
        let id = self.id;
        let d = self._3;
        let v = self._5;
        let c = self._7;
        let x = self._9;

        let m = match t {
            0x70dc => "DC",
            0x70cc => "CC",
            0x70c8 => "C8",
            _ => "..",
        };

        let ff = 0xffff;
        let xor = format!(
            "{:04x} {:02x} {:04x} {:04x} {:04x} {:04x}",
            t ^ ff,
            id ^ 0xff,
            d ^ ff,
            v ^ ff,
            c ^ ff,
            x ^ ff
        );

        write!(
            f,
            "{t:04x}  {id:02x}  {d:04x} {v:04x} {c:04x} {x:04x}  {m}  {xor}"
        )
    }
}

#[derive(FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Gen2Indices([u8; 0x40]);

const GEN2_SMTH_SIZE: usize = size_of::<Gen2PageSmth>();

fn parse_gen2(data: &[u8]) -> Result<bool, String> {
    let size = data.len();
    println!("Trying to parse MFS for Gen 2, size: {size:08x}");

    let mut pages = Vec::<Gen2Page>::new();
    let mut index = Vec::<Gen2PageSmth>::new();

    for offset in (0..size).step_by(GEN2_PAGE_SIZE) {
        let slice = &data[offset..offset + GEN2_PAGE_SIZE];
        let Some(header) = Gen2PageHeader::read_from_prefix(slice) else {
            return Err(format!("could not read header of page @ {offset:08x}"));
        };

        let mut chunks = Vec::<Gen2Chunk>::new();

        let mut pos = 0xd0;

        let n = header.page_num;
        if n > 0 && n != 0xff {
            println!("page {n:03}: read chunks...");
            loop {
                if pos >= GEN2_PAGE_SIZE {
                    println!("page {n:03}: read all chunks, reached {pos:08x}");
                    break;
                }
                let o = offset + pos;
                let ch = Gen2ChunkHeader::read_from_prefix(&data[o..]).unwrap();
                if ch.flags == 0xff || ch.size == 0 {
                    println!("page {n:03}: no chunk @ {pos:08x}, {ch}");
                    // break;
                    pos += 16;
                    continue;
                }
                let size = if ch.size > 2 && ch.flags != 0xb0 {
                    let s = ch.size as usize;
                    // chunks are 16-byte aligned, filled with 0xff to the end
                    let sm = s % 16;
                    if sm == 0 {
                        s
                    } else {
                        s + 16 - sm
                    }
                } else {
                    ch.size as usize * 0x100
                };
                let c = Gen2Chunk {
                    header: ch,
                    offset: pos,
                };
                chunks.push(c);

                if ch.flags == 0xb0 {
                    let x8 = &data[o + 2..o + 10];
                    // NOTE: 3rd byte is always 0x00
                    // Examples:
                    // b0: [0b, 05, 00, 04, 00, 00, 00, 00]
                    // b0: [0b, 12, 00, 00, 00, 00, 00, 00]
                    // b0: [0c, 00, 00, e0, 7a, 33, 95, 52]
                    // b0: [0d, 00, 00, 87, 54, 7d, d8, ec]
                    // b0: [14, 05, 00, 00, ff, ff, ff, ff]
                    // b0: [14, 10, 00, 00, 0c, 00, 00, 04]
                    // b0: [14, 1d, 00, 00, e7, 03, 00, 00]
                    println!("b0: {x8:02x?}");
                }
                pos += size;
            }
        } else {
            println!("page {n:03}: no chunks to read");
        }

        let p = Gen2Page {
            header,
            chunks,
            offset,
        };

        pages.push(p);
    }

    pages.sort_by(|a, b| {
        let na = a.header.page_num;
        let nb = b.header.page_num;
        na.cmp(&nb)
    });

    let mut total_chunks = 0;
    let mut active_chunks = 0;
    for p in &pages {
        let h = p.header;
        let cs = p.chunks.len();
        let po = p.offset;
        println!("{h} @ {po:08x}, {cs} chunks");
        total_chunks += cs;

        if p.is_active() {
            // TODO: evaluate header length, separate from page 0
            const PAGE_HEADER_LENGTH: usize = 0x90;
            let d = Gen2Indices::read_from_prefix(&data[po + PAGE_HEADER_LENGTH..]).unwrap();
            for b in (0..0x40).step_by(0x10) {
                println!("    {:02x?}", &d.0[b..b + 0x10]);
            }
            let fc: Vec<Gen2Chunk> = p
                .chunks
                .clone()
                .into_iter()
                .filter(|c| c.is_active())
                .collect();
            let acs = fc.len();
            println!("{acs} active chunks");
            active_chunks += acs;

            for (i, c) in p.chunks.iter().enumerate() {
                if i % 8 == 0 {
                    println!();
                }
                print!("   {c}");
            }
            println!();
        }
        println!();
    }
    let ps = pages.len();
    println!("{ps} pages, {total_chunks} chunks total, {active_chunks} active");
    println!();

    // first page has MFS magic and some sort of metadata
    let mut i = 0;
    if let Some(p0) = pages.first() {
        let m = u32::from_le_bytes(p0.header.magic);
        if m != GEN2_MAGIC {
            println!("Gen2 MFS: page 0 does not have expected magic");
        } else {
            loop {
                let pos = p0.offset + GEN2_PAGE_HEADER_SIZE + i * GEN2_SMTH_SIZE;
                let smth = Gen2PageSmth::read_from_prefix(&data[pos..]).unwrap();
                if smth._0 == 0xffff {
                    // no idea yet how to get the length here
                    break;
                }
                index.push(smth);
                i += 1;
            }
        }
    }

    /*
    index.sort_by(|a, b| {
        let na = a._0;
        let nb = b._0;
        na.cmp(&nb)
    });
    index.sort_by(|a, b| {
        let na = a._9;
        let nb = b._9;
        na.cmp(&nb)
    });
    index.sort_by(|a, b| {
        let na = a.id;
        let nb = b.id;
        na.cmp(&nb)
    });
    */

    for (i, s) in index.iter().enumerate() {
        println!("{i:04}: {s}");
    }

    let unique = index.iter().map(|i| i.id).collect::<HashSet<_>>();

    println!("{} entries, {} unique", index.len(), unique.len());
    println!();

    Ok(true)
}

pub fn parse(data: &[u8]) -> Result<bool, String> {
    // TODO: This is just a heuristic.
    let t = &data[0..4];
    if let Some(m) = u32::read_from_prefix(t) {
        if m & GEN2_PAGE_MAGIC_MASK == GEN2_PAGE_MAGIC_MASK {
            return parse_gen2(data);
        }
    }

    parse_gen3(data)
}
