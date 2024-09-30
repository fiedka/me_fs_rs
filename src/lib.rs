use std::mem;
use zerocopy::FromBytes;

pub mod cpd;
pub mod fpt;
pub mod mfs;

pub use fpt::ME_FPT;

const FTUP: u32 = u32::from_be_bytes(*b"FTUP");
const DLMP: u32 = u32::from_be_bytes(*b"DLMP");
const FTPR: u32 = u32::from_be_bytes(*b"FTPR");
const NFTP: u32 = u32::from_be_bytes(*b"NFTP");

const MFS: u32 = u32::from_be_bytes(*b"MFS\0");
const AFSP: u32 = u32::from_be_bytes(*b"AFSP");

pub fn parse(data: &[u8]) -> Result<ME_FPT, String> {
    let cpd_bytes = cpd::CPD_MAGIC.as_bytes();
    let mut entries = Vec::<fpt::FPTEntry>::new();
    let mut directories = Vec::<(String, cpd::CodePartitionDirectory)>::new();
    let mut rogue_cpds = Vec::<(usize, String)>::new();

    let mut o = 0;
    while o + 16 + mem::size_of::<fpt::FPT>() <= data.len() {
        o += 16;
        let buf = &data[o..o + 4];
        if buf.eq(cpd_bytes) {
            let cpd = cpd::parse_cpd(&data[o..]).unwrap();
            let n = cpd.header.part_name;
            let name = std::str::from_utf8(&n).unwrap();
            // some names are shorter than 4 bytes and padded with 0x0
            let name = name.trim_end_matches(char::from(0));
            directories.push((String::from(name), cpd));
            rogue_cpds.push((o, name.to_string()));
        }
    }

    println!("CPDs:");
    for (o, dn) in rogue_cpds {
        println!(" - {dn:4} @ 0x{o:08x}");
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
                match n {
                    DLMP | FTPR | NFTP => {
                        let o = base + e.offset as usize;
                        let s = e.size as usize;

                        if o + 4 < data.len() {
                            let buf = &data[o..o + 4];
                            if buf.eq(cpd_bytes) {
                                let cpd = cpd::parse_cpd(&data[o..o + s]).unwrap();
                                directories.push((String::from(name), cpd));
                            }
                        }
                    }

                    MFS | AFSP => {
                        let o = base + e.offset as usize;
                        let s = e.size as usize;
                        if let Err(e) = mfs::parse(&data[o..o + s]) {
                            println!("MFS: {e}");
                        }
                    }
                    _ => {
                        let o = base + e.offset as usize;
                        let s = e.size as usize;

                        if n != FTUP && o + 4 < data.len() {
                            let buf = &data[o..o + 4];
                            if let Ok(sig) = std::str::from_utf8(buf) {
                                if sig == cpd::CPD_MAGIC {
                                    println!("Unknown $CPD in {name} @ 0x{o:08x} (0x{s:08x}).");
                                    continue;
                                }
                            }
                        }
                        println!("Cannot parse {name} (yet), skipping...");
                    }
                }
            }

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
