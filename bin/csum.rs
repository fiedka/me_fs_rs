const T_LO: [u8; 16] = [0, 7, 14, 9, 28, 27, 18, 21, 56, 63, 54, 49, 36, 35, 42, 45];

const T_HI: [u8; 16] = [
    0, 112, 224, 144, 199, 183, 39, 87, 137, 249, 105, 25, 78, 62, 174, 222,
];

pub fn main() {
    let sample = [
        0x87, 0x78, 0x55, 0xaa, 0xb1, 0x28, 0x00, 0x00, 0xcd, 0x00, 0x00, 0x00, 0x1a, 0, 0, 0,
    ];

    println!("{T_LO:02x?}");
    println!("{T_HI:02x?}");

    let mut csum = 1;
    for b in sample {
        let c = (b ^ csum) as usize;
        csum = T_LO[c & 0xf] ^ T_HI[c >> 4];
    }

    println!("{csum:02x}");
}
