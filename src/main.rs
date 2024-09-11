use clap::Parser;
use me_fs_rs::{parse, ME_FPT};
use std::fs;
use std::io;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File to read
    #[arg(short, long)]
    file: String,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let file = args.file;
    println!("Scanning {file} for ME FPT");

    let data = fs::read(file).unwrap();

    if let Ok(fpt) = parse(&data) {
        let ME_FPT { header, entries } = fpt;
        println!("{header:#0x?}");
        println!();
        println!("  name     offset     size      signature             notes");
        for e in entries {
            let o = e.offset as usize;
            let s = e.size as usize;

            let name = std::str::from_utf8(&e.name).unwrap();
            let name = name.trim_end_matches(char::from(0));

            let (part_type, full_name) = me_fs_rs::get_part_info(name);
            let part_info = format!("{part_type:?}: {full_name}");
            let name_offset_size = format!("{name:>4} @ 0x{o:08x}:0x{s:08x}");

            let buf = &data[o..o + 4];
            if let Ok(sig) = std::str::from_utf8(buf) {
                let sig = sig.trim_end_matches(char::from(0));
                println!("- {name_offset_size}: {sig:12}      {part_info}");
            } else {
                println!("- {name_offset_size}: {buf:02x?}  {part_info}");
            }
        }
    }
    Ok(())
}
