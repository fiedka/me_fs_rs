# ME file system parser

This is a work in progress parser for Intel (CS)ME firmware images.
Most of this work is based on other implementations and public research.
References are within the code.

NOTE: Since the knowledge is mostly based on reversing, there is no guarantee
for correctness, completeness or consistency.

## Usage

Either use this crate as a library, or, given a binary, run:
```sh
cargo run --release -- --print firmware.bin
```
