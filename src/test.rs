use pack::{compute_crc, Bytes, Packet, Pid};

use gf;
use reed_solomon::ReedSolomon;

use gf256;

use ax25;

use super::*;

#[test]
fn test_ax25_pack() {
    let mut bytes: Bytes<191> = Bytes::<191>::new();
    bytes.extend(&[
        126, 156, 148, 110, 160, 64, 64, 224, 156, 110, 152, 138, 154, 64, 97, 52, 240, 72, 101,
        108, 108, 111, 32, 119, 111, 114, 108, 100, 126,
    ]);

    let dest_callsign = "NJ7P";
    let source_callsign = "N7LEM";
    let recv_seq_num = 1;
    let poll = true;
    let send_seq_num = 2;
    let pid = Pid::NoL3;
    let data = "Hello world";

    let actual_output: [u8; 191] = Packet::pack_to_ax25(
        dest_callsign,
        source_callsign,
        recv_seq_num,
        poll,
        send_seq_num,
        pid,
        data,
    )
    .bytes;

    assert_eq!(actual_output, bytes.bytes);

    let parsed = ax25::frame::Ax25Frame::from_bytes(&bytes.bytes[1..(bytes.bytes.len())]);
    assert!(parsed.is_ok());

    match parsed {
        Ok(parsed) => {
            assert_eq!(dest_callsign, parsed.destination.callsign);
            assert_eq!(source_callsign, parsed.source.callsign);

            let mut data_bytes = Bytes::<174>::new();
            data_bytes.extend(&data.as_bytes());
            data_bytes.push(126);
            assert_eq!(Vec::from(data_bytes.bytes), parsed.to_bytes()[16..]);
        }
        Err(_) => {}
    }
}

#[test]
fn test_add_gf() {
    assert_eq!(
        (gf::GF256(0x53) + gf::GF256(0xca)).0,
        (gf256::gf256(0x53) + gf256::gf256(0xca)).0
    );
    assert_eq!(
        (gf::GF256(0xff) + gf::GF256(0xff)).0,
        (gf256::gf256(0xff) + gf256::gf256(0xff)).0
    );
}

#[test]
fn test_multiply_gf() {
    assert_eq!(
        (gf::GF256(0x53) * gf::GF256(0xca)).0,
        (gf256::gf256(0x53) * gf256::gf256(0xca)).0
    );
    assert_eq!(
        (gf::GF256(0x32) * gf::GF256(0xf5)).0,
        (gf256::gf256(0x32) * gf256::gf256(0xf5)).0
    );
    assert_eq!(
        (gf::GF256(0xff) * gf::GF256(0xff)).0,
        (gf256::gf256(0xff) * gf256::gf256(0xff)).0
    );
}

#[test]
fn test_divide_gf() {
    assert_eq!(
        (gf::GF256(0x53) / gf::GF256(0xca)).0,
        (gf256::gf256(0x53) / gf256::gf256(0xca)).0
    );
    assert_eq!(
        (gf::GF256(0xfd) / gf::GF256(0xfd)).0,
        (gf256::gf256(0xfd) / gf256::gf256(0xfd)).0
    );
    assert_eq!(
        (gf::GF256(0xff) / gf::GF256(0xff)).0,
        (gf256::gf256(0xff) / gf256::gf256(0xff)).0
    );
}

#[test]
fn test_properties_gf() {
    // Addition properties
    assert_eq!(
        gf::GF256(0x43) + gf::GF256(0xf1),
        gf::GF256(0xf1) + gf::GF256(0x43)
    );
    assert_eq!(
        gf::GF256(0x00) + gf::GF256(0xff),
        gf::GF256(0xff) + gf::GF256(0x00)
    );

    // Multiplication properties
    assert_eq!(
        gf::GF256(0x03) * gf::GF256(0xd6),
        gf::GF256(0xd6) * gf::GF256(0x03)
    );
    assert_eq!(
        gf::GF256(0xff) * gf::GF256(0x00),
        gf::GF256(0x00) * gf::GF256(0xff)
    );

    // Distributivity
    assert_eq!(
        gf::GF256(0x6f) * (gf::GF256(0xf3) + gf::GF256(0x64)),
        gf::GF256(0x6f) * gf::GF256(0xf3) + gf::GF256(0x6f) * gf::GF256(0x64)
    );
}

#[test]
fn test_encode_decode() {
    let rs: ReedSolomon = ReedSolomon::new();

    let mut message: [u8; 191] = [0u8; 191];
    for i in 0..191 {
        message[i] = (i % 256) as u8;
    }

    let mut encoded: [u8; 255] = rs.encode(&message).unwrap();

    encoded[0] ^= 0xFF;
    encoded[1] ^= 0xFF;
    encoded[2] ^= 0xFF;

    let decoded: Option<[u8; 191]> = rs.decode(&mut encoded);

    assert!(decoded.is_some());
    assert_eq!(decoded.unwrap(), message);
}

#[test]
fn test_crc() {
    let crc = compute_crc(&[0x00, 0x00, 0x00, 0x00]);
    assert_eq!(crc, 0x0321);
    let crc = compute_crc(&[0xff, 0xff, 0xff, 0xff]);
    assert_eq!(crc, 0xF0B8);
    let crc = compute_crc(&[0xaa, 0xaa, 0xaa, 0xaa]);
    assert_eq!(crc, 0x59C0);
    let crc = compute_crc(&[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39]);
    assert_eq!(crc, 0x6F91);
}

#[cfg(feature = "fuzz")]
mod fuzzing {
    use crate::{gf, reed_solomon::ReedSolomon};
    use rand::{
        distributions::{Distribution, Standard},
        random, Rng,
    };
    use std::fmt::Debug;

    const FUZZNUM: usize = 10000;

    pub struct Fuzzer {
        iterations: usize,
    }

    impl Fuzzer {
        pub fn new(iterations: usize) -> Self {
            Fuzzer { iterations }
        }

        pub fn fuzz_function<T, O>(&self, test_fn: impl Fn(T) -> O + std::panic::RefUnwindSafe)
        where
            T: Debug + Clone + std::panic::RefUnwindSafe,
            Standard: Distribution<T>, // Fix: Ensure T can be generated using Standard distribution
            O: Debug,
        {
            let mut rng = rand::thread_rng();

            for i in 0..self.iterations {
                let input: T = rng.gen();

                let result = std::panic::catch_unwind(|| test_fn(input.clone()));

                match result {
                    Ok(output) => {
                        println!("Test {}: Input: {:?} -> Output: {:?}", i, input, output)
                    }
                    Err(e) => {
                        let error_message = e
                            .downcast_ref::<String>()
                            .map(|s| s.as_str())
                            .or_else(|| e.downcast_ref::<&str>().copied())
                            .unwrap_or("Unknown error");

                        panic!(
                            "Test {} FAILED: Input {:?} caused a panic!\n{}",
                            i, input, error_message
                        )
                    }
                }
            }
        }
    }

    #[test]
    fn fuzz_add_gf() {
        let fuzzer = Fuzzer::new(FUZZNUM);
        fuzzer.fuzz_function(|x: (u8, u8)| {
            assert_eq!(
                (gf::GF256(x.0) + gf::GF256(x.1)).0,
                (gf256::gf256(x.0) + gf256::gf256(x.1)).0
            );
        });
    }

    #[test]
    fn fuzz_gf_multiply() {
        let fuzzer = Fuzzer::new(FUZZNUM);
        fuzzer.fuzz_function(|x: (u8, u8)| {
            assert_eq!(
                (gf::GF256(x.0) * gf::GF256(x.1)).0,
                (gf256::gf256(x.0) * gf256::gf256(x.1)).0
            );
        });
    }

    #[test]
    fn fuzz_gf_divide() {
        let fuzzer = Fuzzer::new(FUZZNUM);
        fuzzer.fuzz_function(|x: (u8, u8)| {
            if x.1 == 0 {
                assert_eq!((gf::GF256(x.0) / gf::GF256(x.1)).0, 0)
            } else {
                assert_eq!(
                    (gf::GF256(x.0) / gf::GF256(x.1)).0,
                    (gf256::gf256(x.0) / gf256::gf256(x.1)).0
                );
            }
        });
    }

    #[test]
    fn fuzz_properties_gf() {
        let fuzzer = Fuzzer::new(FUZZNUM);
        fuzzer.fuzz_function(|x: (u8, u8, u8)| {
            assert_eq!(
                gf::GF256(x.0) + gf::GF256(x.1),
                gf::GF256(x.1) + gf::GF256(x.0)
            );

            assert_eq!(
                gf::GF256(x.0) * gf::GF256(x.1),
                gf::GF256(x.1) * gf::GF256(x.0)
            );

            assert_eq!(
                gf::GF256(x.0) * (gf::GF256(x.1) + gf::GF256(x.2)),
                gf::GF256(x.0) * gf::GF256(x.1) + gf::GF256(x.0) * gf::GF256(x.2)
            );
        });
    }

    #[test]
    fn fuzz_reed_solomon() {
        for x in 0..33 {
            let rs = ReedSolomon::new();

            let message: [u8; 191] = [0u8; 191];

            if let Some(encoded_message) = rs.encode(&message) {
                let mut codeword = encoded_message;

                for i in 0..x {
                    let a: u8 = random();
                    codeword[i as usize] ^= a; // Corrupt one byte
                }

                if let Some(decoded_message) = rs.decode(&mut codeword) {
                    assert_eq!(decoded_message, message);
                    println!("Decoding succeeded! Message: {:?}", decoded_message);
                } else {
                    println!("Decoding failed: too many errors.");
                }
            } else {
                println!("Encoding failed");
            }
        }
    }

    #[test]
    fn fuzz_ax25_pack() {
        use crate::test::{Bytes, Packet, Pid};

        for _ in 0..100 {
            let dest_callsign = (0..6)
                .map(|_| {
                    let idx = random::<u8>() % 36;
                    if idx < 10 {
                        (b'0' + idx) as char
                    } else {
                        (b'A' + (idx - 10)) as char
                    }
                })
                .collect::<String>();

            let source_callsign = (0..6)
                .map(|_| {
                    let idx = random::<u8>() % 36;
                    if idx < 10 {
                        (b'0' + idx) as char
                    } else {
                        (b'A' + (idx - 10)) as char
                    }
                })
                .collect::<String>();

            let recv_seq_num = random::<u8>() % 8;
            let poll = random::<bool>();
            let send_seq_num = if recv_seq_num == 7 {
                0
            } else {
                recv_seq_num + 1
            };
            let pid = Pid::NoL3;

            let mut rng = rand::thread_rng();
            let length = rng.gen_range(0..174);

            let data = &(0..length)
                .map(|_| rng.gen_range(32..127) as u8 as char)
                .collect::<String>();

            let actual_output: [u8; 191] = Packet::pack_to_ax25(
                &dest_callsign,
                &source_callsign,
                recv_seq_num,
                poll,
                send_seq_num,
                pid,
                data,
            )
            .bytes;

            let parsed =
                ax25::frame::Ax25Frame::from_bytes(&actual_output[1..(actual_output.len())]);
            assert!(parsed.is_ok());

            match parsed {
                Ok(parsed) => {
                    assert_eq!(dest_callsign, parsed.destination.callsign);
                    assert_eq!(source_callsign, parsed.source.callsign);

                    let mut data_bytes = Bytes::<174>::new();
                    data_bytes.extend(&data.as_bytes());
                    data_bytes.push(126);
                    assert_eq!(Vec::from(data_bytes.bytes), parsed.to_bytes()[16..]);
                }
                Err(_) => {}
            }
        }
    }
}
