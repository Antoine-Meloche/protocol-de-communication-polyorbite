use pack::{Bytes, Packet, Pid};

use gf;
use reed_solomon::ReedSolomon;

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
    assert_eq!((gf::GF256(0x32) * gf::GF256(0xf5)).0, (gf256::gf256(0x32) * gf256::gf256(0xf5)).0);
    assert_eq!((gf::GF256(0xff) * gf::GF256(0xff)).0, (gf256::gf256(0xff) * gf256::gf256(0xff)).0);
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

#[test]
fn test_encode_decode() {
    let rs = ReedSolomon::new();
    
    let mut message: [u8; 191] = [0u8; 191];
    for i in 0..191 {
        message[i] = (i % 256) as u8;
    }
    
    let mut encoded: [u8; 255] = rs.encode(&message).unwrap();
    
    encoded[0] ^= 0xFF;
    encoded[1] ^= 0xFF;
    encoded[2] ^= 0xFF;
    
    let decoded = rs.decode(&mut encoded);
    
    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap(), message);
}