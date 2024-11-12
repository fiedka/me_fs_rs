use std::mem;
use zerocopy::FromBytes;

pub mod cpd;
pub mod fit;
pub mod fpt;
pub mod gen2;
pub mod man;
pub mod mfs;

pub use fpt::ME_FPT;

const PARSE_MFS: bool = false;

const FTUP: u32 = u32::from_be_bytes(*b"FTUP");
const DLMP: u32 = u32::from_be_bytes(*b"DLMP");
const FTPR: u32 = u32::from_be_bytes(*b"FTPR");
const NFTP: u32 = u32::from_be_bytes(*b"NFTP");
const MDMV: u32 = u32::from_be_bytes(*b"MDMV");

const MFS: u32 = u32::from_be_bytes(*b"MFS\0");
const AFSP: u32 = u32::from_be_bytes(*b"AFSP");

fn dump48(data: &[u8]) {
    println!("Here are the first 48 bytes:");
    let b = &data[0..0x10];
    println!("{b:02x?}");
    let b = &data[0x10..0x20];
    println!("{b:02x?}");
    let b = &data[0x20..0x30];
    println!("{b:02x?}");
}

const SIG_LUT: u32 = u32::from_le_bytes(*b"LLUT");
const SIG_LZMA: u32 = u32::from_le_bytes([0x36, 0x00, 0x40, 0x00]);

pub fn parse(data: &[u8]) -> Result<ME_FPT, String> {
    let debug = false;

    println!();
    match fit::Fit::new(data) {
        Ok(fit) => {
            println!("{:02x?}", fit.header);
            for e in fit.entries {
                println!("{e}");
            }
        }
        Err(e) => {
            println!("Could not parse FIT: {e}");
        }
    }
    println!();

    let cpd_bytes = cpd::CPD_MAGIC.as_bytes();
    let mut entries = Vec::<fpt::FPTEntry>::new();
    let mut directories = Vec::<cpd::CodePartitionDirectory>::new();

    let mut o = 0;
    while o + 16 + mem::size_of::<fpt::FPT>() <= data.len() {
        o += 16;
        let buf = &data[o..o + 4];
        if buf.eq(cpd_bytes) {
            let cpd = cpd::CodePartitionDirectory::new(&data[o..], o).unwrap();
            directories.push(cpd);
        }
    }

    println!("Scanning for all CPDs:");
    for d in &directories {
        println!(" - {:4} @ 0x{:08x}", d.name, d.offset);
    }

    let mut base = 0;
    while base + 16 + mem::size_of::<fpt::FPT>() <= data.len() {
        // first 16 bytes are potentially other stuff
        let o = base + 16;
        let m = &data[o..o + 4];
        if m.eq(fpt::FPT_MAGIC.as_bytes()) {
            let fpt = fpt::FPT::read_from_prefix(&data[o..]).unwrap();
            for e in 0..fpt.entries as usize {
                // NOTE: Skip $FPT itself
                let pos = o + 32 + e * 32;
                let entry = fpt::FPTEntry::read_from_prefix(&data[pos..]).unwrap();
                entries.push(entry);
            }

            // realign base
            if base % 0x1000 != 0 {
                println!("realign");
                base = o;
            }

            for e in &entries {
                let name = std::str::from_utf8(&e.name).unwrap();
                // some names are shorter than 4 bytes and padded with 0x0
                let name = name.trim_end_matches(char::from(0));
                let n = u32::from_be_bytes(e.name);
                let o = base + (e.offset & 0x003f_ffff) as usize;
                let s = e.size as usize;
                match n {
                    DLMP | FTPR | NFTP => {
                        if o + 4 < data.len() {
                            let buf = &data[o..o + 4];
                            if buf.eq(cpd_bytes) {
                                let cpd =
                                    cpd::CodePartitionDirectory::new(&data[o..o + s], o).unwrap();
                                directories.push(cpd);
                            } else if let Ok(m) = man::Manifest::new(&data[o..]) {
                                println!("Gen 2 directory {name}, {m}");
                                let d = &data[o + man::MANIFEST_SIZE..];
                                let c = m.header.entries as usize;
                                if let Ok(d) = gen2::Directory::new(d, c) {
                                    for e in d.entries {
                                        let pos = o + e.offset as usize;
                                        let sig =
                                            u32::read_from_prefix(&data[pos..pos + 4]).unwrap();
                                        let t = e.compression_type();
                                        let kind = match sig {
                                            SIG_LUT => "LLUT",
                                            SIG_LZMA => "LZMA",
                                            _ => {
                                                dump48(&data[pos..]);
                                                "unknown"
                                            }
                                        };
                                        println!(" - {e}    {:08x} ({kind} {t:?})", pos);
                                        let b = e.bin_map();
                                        println!("     {b}");
                                    }
                                }
                                println!();
                            } else {
                                println!("{name} @ {o:08x} has no CPD signature");
                                if debug {
                                    dump48(&data[o..]);
                                }
                            }
                        }
                    }
                    MDMV => {
                        println!("{name} @ {o:08x}");
                        if let Ok(m) = man::Manifest::new(&data[o..]) {
                            println!("Gen 2 directory {name}, {m}");
                            let d = &data[o + man::MANIFEST_SIZE..];
                            let c = m.header.entries as usize;
                            if let Ok(d) = gen2::Directory::new(d, c) {
                                for e in d.entries {
                                    let pos = o + e.offset as usize;
                                    let sig = u32::read_from_prefix(&data[pos..pos + 4]).unwrap();
                                    let kind = match sig {
                                        SIG_LUT => "LLUT",
                                        SIG_LZMA => "LZMA",
                                        _ => {
                                            dump48(&data[pos..]);
                                            "unknown"
                                        }
                                    };
                                    println!(" - {e}    {:08x} ({kind})", pos);
                                }
                            }
                            println!();
                        }
                    }
                    MFS | AFSP => {
                        if PARSE_MFS {
                            if let Err(e) = mfs::parse(&data[o..o + s]) {
                                println!("MFS: {e}");
                            }
                        }
                    }
                    _ => {
                        if n != FTUP && o + 4 < data.len() {
                            let buf = &data[o..o + 4];
                            if let Ok(sig) = std::str::from_utf8(buf) {
                                if sig == cpd::CPD_MAGIC {
                                    println!("Unknown $CPD in {name} @ 0x{o:08x} (0x{s:08x}).");
                                    continue;
                                }
                            }
                        }
                        println!("Cannot (yet) parse {name} @ 0x{o:08x} (0x{s:08x}), skipping...");
                        if debug {
                            dump48(&data[o..]);
                        }
                        if let Ok(m) = man::Manifest::new(&data[o..]) {
                            println!("MANIFEST; {m}");
                        }
                    }
                }
            }

            // TODO: get MN2 header which includes ME version etc
            // see MEA get_variant + Fiano/CSS ??

            let me_fpt = ME_FPT {
                base,
                header: fpt,
                entries,
                directories,
            };
            return Ok(me_fpt);
        }
        base += 16;
    }
    Err("No $FPT :(".to_string())
}

/*
What is this?! (~/firmware/XCY/GGLK3-VERA/dump/original/0.rom)
Later part of the manifest... some sort of flags + metadata?

0001d3b0: d266 f82a 0100 0000 7003 0000 0000 0000  .f.*....p.......
0001d3c0: 2400 0000 4654 5052 6b65 726e 656c 0000  $...FTPRkernel..
0001d3d0: 0000 0000 0500 0000 1100 0000 4654 5052  ............FTPR
0001d3e0: 7379 736c 6962 0000 0000 0000 0500 0000  syslib..........
0001d3f0: 1100 0000 5242 4550 7262 6500 0000 0000  ....RBEPrbe.....
0001d400: 0000 0000 0500 0000 1100 0000 4654 5052  ............FTPR
0001d410: 6275 7000 0000 0000 0000 0000 0500 0000  bup.............
0001d420: 1100 0000 4e46 5450 6576 7464 6973 7000  ....NFTPevtdisp.
0001d430: 0000 0000 0100 0700 1100 0000 4e46 5450  ............NFTP
*/

/*
Some entries here have 8 byte magics or XXID...?
EFFS - embedded flash file system (?)
FOVD - ???; also on Skochinsky's slides, see
https://recon.cx/2014/slides/Recon%202014%20Skochinsky.pdf
NVCL and some other have lots of ffff...?
~/firmware/XMG/C404/extracted/BIOS/BIOS.BIN/XMGBF.B05

00001000: 2020 800f 4000 0024 0000 0000 0000 0000    ..@..$........
00001010: 2446 5054 1300 0000 2010 30f7 0700 6400  $FPT.... .0...d.
00001020: 1000 0000 01fc ffff 0900 0000 1600 bb05  ................
00001030: 5053 564e 4b52 4944 c00b 0000 4000 0000  PSVNKRID....@...
00001040: 0100 0000 0100 0000 0000 0000 8387 0100  ................
00001050: 464f 5644 4b52 4944 000c 0000 0004 0000  FOVDKRID........
00001060: 0100 0000 0100 0000 0000 0000 8307 0000  ................
00001070: 4d44 4553 4d44 4944 0010 0000 0010 0000  MDESMDID........
00001080: 0100 0000 0100 0000 0000 0000 8323 0000  .............#..
00001090: 4643 5253 4f53 4944 0020 0000 0010 0000  FCRSOSID. ......
000010a0: 0100 0000 0100 0000 0000 0000 8323 0000  .............#..
000010b0: 4546 4653 4f53 4944 0030 0000 0000 0400  EFFSOSID.0......
000010c0: 400b 0000 6027 0000 0000 0000 04a7 0000  @...`'..........
000010d0: 4e56 434c ffff ffff ffff ffff c969 0000  NVCL.........i..
000010e0: ffff ffff ffff ffff ffff ffff 0200 0000  ................
000010f0: 4e56 4350 ffff ffff ffff ffff c0a3 0000  NVCP............
00001100: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001110: 4e56 484d ffff ffff ffff ffff 5800 0000  NVHM........X...
00001120: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001130: 4e56 4a43 ffff ffff ffff ffff a03d 0000  NVJC.........=..
00001140: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001150: 4e56 4b52 ffff ffff ffff ffff 305c 0000  NVKR........0\..
00001160: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001170: 4e56 4e46 ffff ffff ffff ffff 5f17 0000  NVNF........_...
00001180: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001190: 4e56 5348 ffff ffff ffff ffff c022 0000  NVSH........."..
000011a0: ffff ffff ffff ffff ffff ffff 0200 0000  ................
000011b0: 4e56 534d ffff ffff ffff ffff e81d 0000  NVSM............
000011c0: ffff ffff ffff ffff ffff ffff 0200 0000  ................
000011d0: 4e56 5444 ffff ffff ffff ffff eb1f 0000  NVTD............
000011e0: ffff ffff ffff ffff ffff ffff 0200 0000  ................
000011f0: 4e56 554b ffff ffff ffff ffff 4089 0000  NVUK........@...
00001200: ffff ffff ffff ffff ffff ffff 0200 0000  ................
00001210: 474c 5554 ffff ffff 0030 0400 0040 0000  GLUT.....0...@..
00001220: 0100 0000 0100 0000 0000 0000 83a7 0000  ................
00001230: 4654 5052 ffff ffff 0070 0400 0080 0800  FTPR.....p......
00001240: 0100 0000 0100 0000 0000 0000 80a7 0000  ................
00001250: 4e46 5450 ffff ffff 00f0 0c00 0070 0700  NFTP.........p..
00001260: 0100 0000 0100 0000 0000 0000 80a7 0000  ................
00001270: 4d44 4d56 ffff ffff 0060 1400 0070 0300  MDMV.....`...p..
00001280: 0100 0000 0100 0000 0000 0000 80a7 0000  ................
*/
