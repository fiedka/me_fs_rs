use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};
use zerocopy::FromBytes;
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes};

const VENDOR_INTEL: u16 = 0x8086;
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
pub struct Vendor(u16);

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

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Header {
    _0: [u8; 16],
    pub vendor: Vendor,
    _12: u16,
    pub date: Date,
    _16: u32,
    pub magic: [u8; 4],
    _20: u32,
    pub version: Version,
    _2b: u32,
}

#[derive(AsBytes, FromBytes, FromZeroes, Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C)]
pub struct Manifest {
    pub header: Header,
}

impl<'a> Manifest {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        let header = Header::read_from_prefix(data).unwrap();

        if header.magic != *MANIFEST2_MAGIC {
            let err = format!("manifest magic not found, got: {:02x?}", header.magic);
            return Err(err);
        }

        let m = Self { header };

        Ok(m)
    }
}

impl Display for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = self.header.version;
        let date = self.header.date;
        let ven = self.header.vendor;
        write!(f, "vendor {ven}, version {ver} {date}")
    }
}
