use std::mem;
use zerocopy::FromBytes;

pub mod dir;
pub mod fit;
pub mod fpt;
pub mod mfs;

pub use fpt::ME_FPT;
use fpt::{AFSP, DLMP, EFFS, FTPR, FTUP, MDMV, MFS, NFTP};

const PARSE_MFS: bool = false;

fn dump48(data: &[u8]) {
    println!("Here are the first 48 bytes:");
    let b = &data[0..0x10];
    println!("{b:02x?}");
    let b = &data[0x10..0x20];
    println!("{b:02x?}");
    let b = &data[0x20..0x30];
    println!("{b:02x?}");
}

const SCAN_FOR_ALL_CPDS: bool = false;

pub fn parse(data: &[u8]) -> Result<ME_FPT, String> {
    let debug = false;

    println!();
    match fit::Fit::new(data) {
        Ok(fit) => {
            println!("FIT @ {:08x}, {}", fit.offset, fit.header);
            for e in fit.entries {
                println!("{e}");
            }
        }
        Err(e) => {
            println!("Could not parse FIT: {e}");
        }
    }
    println!();

    let cpd_bytes = dir::gen3::CPD_MAGIC.as_bytes();
    let mut entries = Vec::<fpt::FPTEntry>::new();
    let mut gen2dirs = Vec::<dir::gen2::Directory>::new();
    let mut directories = Vec::<dir::gen3::CodePartitionDirectory>::new();

    // Scann for all CPDs (there may be some not listed in FPT)
    if SCAN_FOR_ALL_CPDS {
        let mut o = 0;
        while o < data.len() {
            let buf = &data[o..o + 4];
            if buf.eq(cpd_bytes) {
                let Ok(cpd) = dir::gen3::CodePartitionDirectory::new(data[o..].to_vec(), o) else {
                    continue;
                };
                directories.push(cpd);
            }
            o += 16;
        }
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

            // realign base; what does this indicate?
            if base % 0x1000 != 0 {
                println!("realign");
                base = o;
            }

            for e in &entries {
                let name = match std::str::from_utf8(&e.name) {
                    // some names are shorter than 4 bytes and padded with 0x0
                    Ok(n) => n.trim_end_matches('\0').to_string(),
                    Err(_) => format!("{:02x?}", &e.name),
                };
                let n = u32::from_be_bytes(e.name);
                let o = base + (e.offset & 0x003f_ffff) as usize;
                let s = e.size as usize;
                match n {
                    MDMV | DLMP | FTPR | NFTP => {
                        if o + 4 < data.len() {
                            let buf = &data[o..o + 4];
                            if buf.eq(cpd_bytes) {
                                if let Ok(cpd) = dir::gen3::CodePartitionDirectory::new(
                                    data[o..o + s].to_vec(),
                                    o,
                                ) {
                                    directories.push(cpd);
                                }
                            } else if let Ok(dir) = dir::gen2::Directory::new(&data[o..], o) {
                                gen2dirs.push(dir);
                            } else {
                                println!("{name} @ {o:08x} has no CPD signature");
                                if debug {
                                    dump48(&data[o..]);
                                }
                            }
                        }
                    }
                    MFS | AFSP | EFFS => {
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
                                if sig == dir::gen3::CPD_MAGIC {
                                    println!("Unknown $CPD in {name} @ 0x{o:08x} (0x{s:08x}).");
                                    continue;
                                }
                            }
                        }
                        println!("Cannot (yet) parse {name} @ 0x{o:08x} (0x{s:08x}), skipping...");
                        if debug {
                            dump48(&data[o..]);
                        }
                        if let Ok(m) = dir::man::Manifest::new(&data[o..]) {
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
                gen2dirs,
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
