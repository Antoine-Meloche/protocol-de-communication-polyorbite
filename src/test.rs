use ax25;
use gf;
use gf256;

use reed_solomon::{Decoder, Encoder};

use pack::{compute_crc, Bytes, Packet, Pid};

use super::*;

#[test]
fn test_ax25_pack() {
    let dest_callsign: [u8; 6] = *b"  NJ7P";
    let source_callsign: [u8; 6] = *b" N7LEM";
    let recv_seq_num = 1;
    let poll = true;
    let send_seq_num = 2;
    let pid = Pid::NoL3;

    let mut data: [u8; 171] = [0u8; 171];
    let data_str = "Hello world".as_bytes();
    data[..data_str.len()].copy_from_slice(data_str);

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

    let mut to_parse = actual_output.clone();

    let mut removed_count = 0;
    for i in (0..to_parse.len()).rev() {
        if to_parse[i] != 0 {
            to_parse[i] = 0;
            removed_count += 1;

            if removed_count == 3 {
                to_parse[i] = 0x7E;
                break;
            }
        }
    }

    let parsed = ax25::frame::Ax25Frame::from_bytes(&to_parse[1..(to_parse.len())]);
    assert!(parsed.is_ok());

    match parsed {
        Ok(parsed) => {
            assert_eq!(dest_callsign, parsed.destination.callsign.as_bytes());
            assert_eq!(source_callsign, parsed.source.callsign.as_bytes());

            let mut data_bytes = Bytes::<174>::new();
            data_bytes.extend(&data);
            data_bytes.push(126);
            assert_eq!(Vec::from(data_bytes.bytes), parsed.to_bytes()[16..]);
        }
        Err(_) => {}
    }
}

#[test]
fn test_fx25() {
    let dest_callsign = *b"NJ7P  ";
    let source_callsign = *b"N7LEM ";
    let recv_seq_num = 1;
    let poll = true;
    let send_seq_num = 2;
    let pid = Pid::NoL3;

    let mut data: [u8; 171] = [0; 171];
    let data_str = "Hello world".as_bytes();
    data[..data_str.len()].copy_from_slice(data_str);

    let packet = Packet::pack_to_ax25(
        dest_callsign,
        source_callsign,
        recv_seq_num,
        poll,
        send_seq_num,
        pid,
        data,
    );
    let packet_control = packet.control.clone();

    let mut fx25_packet = packet.pack_to_fx25();

    fx25_packet[0] ^= 0xFF;
    fx25_packet[10] ^= 0xFF;
    fx25_packet[50] ^= 0xFF;
    fx25_packet[67] ^= 0xFF;

    let decoded = Packet::decode_fx25(fx25_packet);

    assert!(decoded.is_ok());

    let decoded = decoded.unwrap();
    assert_eq!(decoded.source_addr.callsign, source_callsign);
    assert_eq!(decoded.dest_addr.callsign, dest_callsign);
    assert_eq!(decoded.control.to_byte(), packet_control.to_byte());
    assert_eq!(decoded.pid as u8, pid as u8);
    assert_eq!(decoded.payload.data, data);
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
    let mut message: [u8; 191] = [0u8; 191];
    for i in 0..191 {
        message[i] = (i % 256) as u8;
    }

    let ecc_len = 64;

    let encoder = Encoder::new(ecc_len);
    let decoder = Decoder::new(ecc_len);

    let mut encoded = encoder.encode(&message[..]);

    encoded[0] ^= 0xFF;
    encoded[1] ^= 0xFF;
    encoded[2] ^= 0xFF;

    let known_errors = [0];
    let decoded = decoder.correct(&mut encoded, Some(&known_errors));

    assert!(decoded.is_ok());
    assert_eq!(decoded.unwrap().data(), message);
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

// #[cfg(feature = "fuzz")]
mod fuzzing {
    use crate::gf;
    use rand::{
        distributions::{Distribution, Standard},
        random, Rng,
    };
    use std::fmt::Debug;

    use reed_solomon::{Decoder, Encoder};

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
        let mut rng = rand::thread_rng();

        for x in 0..255 {
            let mut message: [u8; 191] = [0u8; 191];
            for i in 0..191 {
                message[i] = (i % 256) as u8;
            }

            let ecc_len = 64;

            let encoder = Encoder::new(ecc_len);
            let decoder = Decoder::new(ecc_len);

            let mut encoded = encoder.encode(&message[..]);

            for _ in 0..=x {
                encoded[rng.gen_range(0..255)] ^= 0xFF;
            }

            let known_errors = [0];
            let decoded = decoder.correct(&mut encoded, Some(&known_errors));

            if x < 32 {
                assert!(decoded.is_ok());
                assert_eq!(decoded.unwrap().data(), message);
            } else {
                if decoded.is_ok() {
                    assert_eq!(decoded.unwrap().data(), message);
                }
            }
        }
    }

    #[test]
    fn fuzz_ax25_pack() {
        use crate::test::{Bytes, Packet, Pid};

        for _ in 0..100 {
            let mut dest_callsign: [u8; 6] = [0; 6];
            for i in 0..6 {
                let idx = random::<u8>() % 36;
                if idx < 10 {
                    dest_callsign[i] = (b'0' + idx) as u8;
                } else {
                    dest_callsign[i] = (b'A' + (idx - 10)) as u8;
                }
            }

            let mut source_callsign: [u8; 6] = [0; 6];
            for i in 0..6 {
                let idx = random::<u8>() % 36;
                if idx < 10 {
                    source_callsign[i] = (b'0' + idx) as u8;
                } else {
                    source_callsign[i] = (b'A' + (idx - 10)) as u8;
                }
            }

            let recv_seq_num = random::<u8>() % 8;
            let poll = random::<bool>();
            let send_seq_num = if recv_seq_num == 7 {
                0
            } else {
                recv_seq_num + 1
            };
            let pid = Pid::NoL3;

            let mut rng = rand::thread_rng();
            let length = rng.gen_range(0..171);

            let mut data: [u8; 171] = [0; 171];
            data[0..length].copy_from_slice(
                &(0..length)
                    .map(|_| rng.gen_range(32..127) as u8)
                    .collect::<Vec<u8>>(),
            );

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

            let mut to_parse = actual_output.clone();

            for i in (0..to_parse.len()).rev() {
                if to_parse[i] == 0x7E {
                    to_parse[i - 2] = 0x7E;
                    to_parse[i - 1] = 0;
                    to_parse[i] = 0;
                    break;
                }
            }

            let parsed = ax25::frame::Ax25Frame::from_bytes(&to_parse[1..(to_parse.len())]);
            assert!(parsed.is_ok());

            match parsed {
                Ok(parsed) => {
                    assert_eq!(dest_callsign, parsed.destination.callsign.as_bytes());
                    assert_eq!(source_callsign, parsed.source.callsign.as_bytes());

                    let mut data_bytes = Bytes::<174>::new();
                    data_bytes.extend(&data);
                    data_bytes.push(0x7E);
                    assert_eq!(Vec::from(data_bytes.bytes), parsed.to_bytes()[16..]);
                }
                Err(_) => {}
            }
        }
    }

    #[test]
    fn fuzz_fx25_pack() {
        use crate::test::{Packet, Pid};

        for x in 0..255 {
            let mut dest_callsign: [u8; 6] = [0; 6];
            for i in 0..6 {
                let idx = random::<u8>() % 36;
                if idx < 10 {
                    dest_callsign[i] = (b'0' + idx) as u8;
                } else {
                    dest_callsign[i] = (b'A' + (idx - 10)) as u8;
                }
            }

            let mut source_callsign: [u8; 6] = [0; 6];
            for i in 0..6 {
                let idx = random::<u8>() % 36;
                if idx < 10 {
                    source_callsign[i] = (b'0' + idx) as u8;
                } else {
                    source_callsign[i] = (b'A' + (idx - 10)) as u8;
                }
            }

            let recv_seq_num = random::<u8>() % 8;
            let poll = random::<bool>();
            let send_seq_num = if recv_seq_num == 7 {
                0
            } else {
                recv_seq_num + 1
            };
            let pid = Pid::NoL3;

            let mut rng = rand::thread_rng();
            let length = rng.gen_range(0..171);

            let mut data: [u8; 171] = [0; 171];
            data[0..length].copy_from_slice(
                &(0..length)
                    .map(|_| rng.gen_range(32..127) as u8)
                    .collect::<Vec<u8>>(),
            );

            let packet = Packet::pack_to_ax25(
                dest_callsign,
                source_callsign,
                recv_seq_num,
                poll,
                send_seq_num,
                pid,
                data,
            );
            let packet_control = packet.control.clone();

            let mut fx25_packet = packet.pack_to_fx25();

            for _ in 0..=x {
                fx25_packet[rng.gen_range(0..255)] ^= 0xFF;
            }

            let decoded = Packet::decode_fx25(fx25_packet);

            if x < 32 {
                assert!(decoded.is_ok());

                let decoded = decoded.unwrap();
                assert_eq!(decoded.source_addr.callsign, source_callsign);
                assert_eq!(decoded.dest_addr.callsign, dest_callsign);
                assert_eq!(decoded.control.to_byte(), packet_control.to_byte());
                assert_eq!(decoded.pid as u8, pid as u8);
                assert_eq!(decoded.payload.data, data);
            } else {
                if decoded.is_ok() {
                    let decoded = decoded.unwrap();
                    assert_eq!(decoded.source_addr.callsign, source_callsign);
                    assert_eq!(decoded.dest_addr.callsign, dest_callsign);
                    assert_eq!(decoded.control.to_byte(), packet_control.to_byte());
                    assert_eq!(decoded.pid as u8, pid as u8);
                    assert_eq!(decoded.payload.data, data);
                }
            }
        }
    }
}
