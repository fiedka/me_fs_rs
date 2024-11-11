use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

const VENDOR_INTEL: u32 = 0x8086;
const MANIFEST2_MAGIC: &[u8] = b"$MN2";

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
    build: u16,
}

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Version {
            major,
            minor,
            patch,
            build,
        } = self;
        write!(f, "{major}.{minor}.{patch}.{build}")
    }
}

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Date {
    day: u8,
    month: u8,
    year: u16,
}

impl Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Date { year, month, day } = self;
        write!(f, "{year:04x}-{month:02x}-{day:02x}")
    }
}

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Vendor(u32);

impl Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = self.0;
        let v = match id {
            VENDOR_INTEL => "Intel",
            _ => "unknown",
        };
        write!(f, "{v} ({id:04x})")
    }
}

// https://github.com/skochinsky/me-tools me_unpack.py MeManifestHeader
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C)]
pub struct Header {
    pub mod_type: u16,
    pub mod_subtype: u16,
    pub header_len: u32, // in dwords, usually 0xa1, i.e., 0x284 bytes
    pub header_ver: u32,
    pub flags: u32,
    pub vendor: Vendor,
    pub date: Date,
    pub size: u32, // in dwords, dword size is 32bit
    pub magic: [u8; 4],
    // NOTE: only for Gen 2 ME firmware
    pub entries: u32,
    pub version: Version,
    xx0: u32,          // e.g. 0x0000_0001
    _30: u32,          // e.g. all zero
    xxx: u32,          // e.g. 0x0000_0003
    _38: [u8; 0x40],   // e.g. all zero
    pub key_size: u32, // in dwords
    pub scratch_size: u32,
}

const HEADER_SIZE: usize = core::mem::size_of::<Header>();
const KEY_SIZE: usize = 0x100;

#[derive(AsBytes, FromBytes, FromZeroes, Clone, Copy, Debug)]
#[repr(C)]
pub struct Manifest {
    pub header: Header,
    pub rsa_pub_key: [u8; KEY_SIZE],
    pub rsa_pub_exp: u32,
    pub rsa_sig: [u8; KEY_SIZE],
}

pub const MANIFEST_SIZE: usize = core::mem::size_of::<Manifest>();

impl<'a> Manifest {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        let header = Header::read_from_prefix(data).unwrap();

        if header.magic != *MANIFEST2_MAGIC {
            let err = format!("manifest magic not found, got: {:02x?}", header.magic);
            return Err(err);
        }

        let o = HEADER_SIZE;
        let rsa_pub_key: [u8; KEY_SIZE] = data[o..o + KEY_SIZE].try_into().unwrap();
        let o = o + KEY_SIZE;
        let rsa_pub_exp = u32::read_from_prefix(&data[o..o + 4]).unwrap();
        let o = o + 4;
        let rsa_sig: [u8; KEY_SIZE] = data[o..o + KEY_SIZE].try_into().unwrap();

        let m = Self {
            header,
            rsa_pub_key,
            rsa_pub_exp,
            rsa_sig,
        };

        Ok(m)
    }
}

impl Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = self.header.version;
        let date = self.header.date;
        let ven = self.header.vendor;
        let e = self.header.entries;
        write!(f, "vendor {ven}, version {ver} {date}, {e} entries")
    }
}
