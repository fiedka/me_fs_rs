use zerocopy::FromBytes;

// We compile to Wasm, so this is needed
// https://gist.github.com/JakeHartnell/2c1fa387f185f5dc46c9429470a2e2be
#[doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/doc/me_gen2_mfs.md"))]
pub mod gen2;
pub mod gen3;

const GEN2_PAGE_MAGIC_MASK: u32 = 0xfff0_7800;

pub fn parse(data: &[u8]) -> Result<bool, String> {
    // TODO: This is just a heuristic.
    let t = &data[0..4];
    if let Some(m) = u32::read_from_prefix(t) {
        if m & GEN2_PAGE_MAGIC_MASK == GEN2_PAGE_MAGIC_MASK {
            // TODO: library should not print; remove verbose flag eventually
            return gen2::parse(data, true);
        }
    }

    gen3::parse(data)
}
