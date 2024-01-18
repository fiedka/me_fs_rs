#![no_main]
use libfuzzer_sys::fuzz_target;
use me_fs_rs;

const MAX_INPUT_SIZE: usize = 1024;

fn do_fuzz(data: &[u8]) {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }
    let _res = me_fs_rs::parse(data);
}

fuzz_target!(|data: &[u8]| {
    do_fuzz(data);
});
