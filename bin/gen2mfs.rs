use clap::Parser;
use me_fs_rs::mfs::gen2::parse;
use std::fs;
use std::io;

/// Parse Intel ME Gen2 MFS
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Print verbosely
    #[arg(required = false, short, long)]
    verbose: bool,

    /// File to read
    #[arg(index = 1)]
    file: String,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let file = args.file;
    println!("Parsing MFS in {file}");

    let data = fs::read(file).unwrap();
    match parse(&data, args.verbose) {
        Ok(_) => {}
        Err(e) => {
            println!("Error: {e}");
        }
    }
    Ok(())
}
