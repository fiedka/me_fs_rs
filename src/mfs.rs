use zerocopy::FromBytes;

pub mod gen2;
pub mod gen3;

const GEN2_PAGE_MAGIC_MASK: u32 = 0xfff0_7800;

pub fn parse(data: &[u8]) -> Result<bool, String> {
    // TODO: This is just a heuristic.
    let t = &data[0..4];
    if let Some(m) = u32::read_from_prefix(t) {
        if m & GEN2_PAGE_MAGIC_MASK == GEN2_PAGE_MAGIC_MASK {
            return gen2::parse(data);
        }
    }

    gen3::parse(data)
}
