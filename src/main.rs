use clap::Parser;
use me_fs_rs::fit::Fit;
use me_fs_rs::{
    dir::gen2::Directory as Gen2Dir, dir::gen3::CodePartitionDirectory, fpt::FPTEntry, parse,
    ME_FPT,
};
use std::fs;
use std::io;

/// Print Intel (CS)ME FPT information
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Print header data
    #[arg(required = false, short, long)]
    print: bool,

    /// Print verbosely, including partitions and directories
    #[arg(required = false, short, long)]
    verbose: bool,

    /// Verbose output plus extra information for debugging
    #[arg(required = false, short, long)]
    debug: bool,

    /// File to read
    #[arg(index = 1)]
    file: String,
}

fn print_gen2_dirs(dirs: &Vec<Gen2Dir>) {
    println!("Gen 2 Directories:");
    for dir in dirs {
        println!("{dir}");
        for e in &dir.entries {
            let pos = dir.offset + e.offset as usize;
            /*
            let sig =
                u32::read_from_prefix(&data[pos..pos + 4]).unwrap();
            let kind = match sig {
                SIG_LUT => "LLUT",
                SIG_LZMA => "LZMA",
                _ => {
                    dump48(&data[pos..]);
                    "unknown"
                }
            };
            */
            let kind = "...";
            let t = e.compression_type();
            let b = e.bin_map();
            println!(" - {e}    {pos:08x} {t:?} ({kind})\n     {b}");
        }
        println!();
    }
}

fn print_gen3_dirs(dirs: &Vec<CodePartitionDirectory>) {
    println!("Gen 3 Directories:");
    for d in dirs {
        println!();
        let checksum = d.header.version_or_checksum;
        let o = d.offset;
        println!("{} @ {o:08x}, checksum or version: {checksum:08x}", d.name);
        match &d.manifest {
            Ok(m) => println!("{m}"),
            Err(e) => println!("{e}"),
        }

        println!("  file name        offset    end       size           compression flags");
        let mut entries = d.entries.clone();
        entries.sort_by_key(|e| e.offset);
        for e in entries {
            println!("  {e}");
        }
    }
}

fn print_fpt_entries(entries: &mut [FPTEntry]) {
    println!("  name     offset     end         size       type  notes");
    entries.sort_by_key(|e| e.offset);
    for e in entries {
        println!("- {e}");
    }
}

fn print_fit(fit: &Result<Fit, String>) {
    match fit {
        Ok(fit) => {
            println!("FIT @ {:08x}, {}", fit.offset, fit.header);
            for e in &fit.entries {
                println!("{e}");
            }
        }
        Err(e) => {
            println!("Could not parse FIT: {e}");
        }
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let file = args.file;
    println!("Scanning {file} for ME FPT");

    let data = fs::read(file).unwrap();

    println!();
    match parse(&data, args.debug) {
        Ok(fpt) => {
            let ME_FPT {
                base,
                header,
                entries,
                directories,
                gen2dirs,
                fit,
            } = fpt;
            if args.verbose {
                println!("FPT at 0x{base:08x}: {header:#0x?}");
            } else if args.print {
                println!("FPT at 0x{base:08x}: Version {}", header.header_ver);
            }
            if args.print || args.verbose || args.debug {
                print_fpt_entries(&mut entries.clone());
                println!();
                print_fit(&fit);
            }
            if args.verbose || args.debug {
                println!();
                if !gen2dirs.is_empty() {
                    print_gen2_dirs(&gen2dirs);
                }
                if !directories.is_empty() {
                    print_gen3_dirs(&directories);
                }
            }
        }
        Err(e) => {
            println!("Error: {e}");
        }
    }
    Ok(())
}
