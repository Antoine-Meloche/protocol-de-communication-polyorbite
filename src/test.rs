use pack::{Bytes, Packet, Pid};

use gf;
// use reed_solomon::RS255_191;

use gf256;

use super::*;

#[test]
fn test_ax25_pack() {
    let mut bytes: Bytes<191> = Bytes::<191>::new();
    bytes.extend(&[0x7E, 156, 148, 110, 160, 64, 64, 224, 156, 110, 152, 138, 154, 64, 97, 52, 240, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 126]);
    let actual_output: [u8; 191] = Packet::pack_to_ax25("NJ7P", "N7LEM", 1, true, 2, Pid::NoL3, "Hello world").bytes;

    assert_eq!(actual_output, bytes.bytes);
}

#[test]
fn test_add_gf() {
    assert_eq!((gf::GF256(0x53) + gf::GF256(0xca)).0, (gf256::gf256(0x53) + gf256::gf256(0xca)).0);
    assert_eq!((gf::GF256(0xff) + gf::GF256(0xff)).0, (gf256::gf256(0xff) + gf256::gf256(0xff)).0);
}

#[test]
fn test_multiply_gf() {
    assert_eq!((gf::GF256(0x53) * gf::GF256(0xca)).0, (gf256::gf256(0x53) * gf256::gf256(0xca)).0);
    // assert_eq!((gf::GF256(0x32) * gf::GF256(0xf5)).0, (gf256::gf256(0x32) * gf256::gf256(0xf5)).0);
    // assert_eq!((gf::GF256(0xff) * gf::GF256(0xff)).0, (gf256::gf256(0xff) * gf256::gf256(0xff)).0);
}

#[test]
fn test_divide_gf() {
    assert_eq!((gf::GF256(0x53) / gf::GF256(0xca)).0, (gf256::gf256(0x53) / gf256::gf256(0xca)).0);
    assert_eq!((gf::GF256(0xfd) / gf::GF256(0xfd)).0, (gf256::gf256(0xfd) / gf256::gf256(0xfd)).0);
    assert_eq!((gf::GF256(0xff) / gf::GF256(0xff)).0, (gf256::gf256(0xff) / gf256::gf256(0xff)).0);
}

#[test]
fn test_properties_gf() {
    // Addition properties
    assert_eq!(gf::GF256(0x43) + gf::GF256(0xf1), gf::GF256(0xf1) + gf::GF256(0x43));
    assert_eq!(gf::GF256(0x00) + gf::GF256(0xff), gf::GF256(0xff) + gf::GF256(0x00));

    // Multiplication properties
    assert_eq!(gf::GF256(0x03) * gf::GF256(0xd6), gf::GF256(0xd6) * gf::GF256(0x03));
    assert_eq!(gf::GF256(0xff) * gf::GF256(0x00), gf::GF256(0x00) * gf::GF256(0xff));

    // Distributivity
    assert_eq!(gf::GF256(0x6f) * (gf::GF256(0xf3) + gf::GF256(0x64)), gf::GF256(0x6f) * gf::GF256(0xf3) + gf::GF256(0x6f) * gf::GF256(0x64));
}

// #[test]
// fn test_rs_encode_decode() {
//     let rs = RS255_191::new();

//     let mut message = [0u8; 255];
//     for i in 0..191 {
//         message[i] = i as u8;
//     }

//     let mut encoded = message;
//     rs.encode(&mut encoded);

//     assert_eq!(rs.check(&encoded), 0);

//     let mut corrupted = encoded;
//     corrupted[0] ^= 0x01;

//     assert!(rs.check(&corrupted) > 0);
// }