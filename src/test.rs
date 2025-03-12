use ax25;
use gf;
use gf256;

use reed_solomon::{Decoder, Encoder};

use pack::{compute_crc, Bytes, Packet, Pid};
use sign::{sign_data, verify_data};

use crate::pack::{Control, CorrelationTag, Fx25Fields, Supervisory};

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
fn test_sub_gf() {
    assert_eq!(
        (gf::GF256(0x53) - gf::GF256(0xca)).0,
        (gf256::gf256(0x53) - gf256::gf256(0xca)).0
    );
    assert_eq!(
        (gf::GF256(0xff) - gf::GF256(0xff)).0,
        (gf256::gf256(0xff) - gf256::gf256(0xff)).0
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
    assert_eq!((gf::GF256(0x53) / gf::GF256(0)).0, 0);
}

#[test]
fn test_inverse_gf() {
    assert_eq!(gf::GF256::inverse(0), 0);
}

#[test]
fn test_properties_gf() {
    assert_eq!(gf::GF256(0), gf::GF256::new(0));

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

#[test]
fn test_sign_data() {
    let data: [u8; 16] = [
        0x31, 0x6f, 0xaf, 0x73, 0x44, 0x02, 0x00, 0x00, 0x43, 0x42, 0x64, 0xff, 0xf1, 0xca, 0xcc,
        0x45,
    ];
    let key = b"0123456789abcdef";

    let signed = sign_data(&data, key);
    assert_eq!(signed.len(), 50);

    assert!(verify_data(&data, signed, key));
}

#[test]
fn test_sign_empty() {
    let data = b"";
    let key = b"0123456789abcdef";

    let signed = sign_data(data, key);
    assert_eq!(signed.len(), 50);
    assert!(verify_data(data, signed, key));
}

#[test]
fn test_sign_large() {
    let data = [0xFF; 1024];
    let key = b"0123456789abcdef";

    let signed = sign_data(&data, key);
    assert_eq!(signed.len(), 50);
    assert!(verify_data(&data, signed, key))
}

#[test]
fn test_sign_wrong_key() {
    let data = b"Hello, World!";
    let key = b"0123456789abcdef";
    let dec_key = b"thisthewrong_key";

    let signed = sign_data(data, key);
    assert_eq!(signed.len(), 50);

    assert!(!verify_data(data, signed, dec_key));
}

#[test]
fn test_sign_tampered_data() {
    let data = b"";
    let key = b"0123456789abcdef";

    let mut signed = sign_data(data, key);

    signed[0] ^= 0xFF;

    assert!(!verify_data(data, signed, key));
}

#[test]
fn test_sign_tampered_hash() {
    let data = b"";
    let key = b"0123456789abcdef";

    let mut signed = sign_data(data, key);

    signed[data.len()] ^= 0xFF;

    assert!(!verify_data(data, signed, key));
}

#[test]
fn test_sign_tampered_nonce() {
    let data = b"";
    let key = b"0123456789abcdef";

    let mut signed = sign_data(data, key);

    signed[data.len() + 16] ^= 0xFF;

    assert!(!verify_data(data, signed, key));
}

#[test]
fn test_correlation_tag() {
    let correlation_tag =
        CorrelationTag::find_closest_tag(&(CorrelationTag::Tag0B as u64 + 1).to_le_bytes());
    assert_eq!(correlation_tag as u8, CorrelationTag::Tag0B as u8);

    let correlation_tag_incorrect_length = CorrelationTag::find_closest_tag(&[0]);
    assert_eq!(
        correlation_tag_incorrect_length as u8,
        CorrelationTag::Tag09 as u8
    );
}

#[test]
fn test_bytes() {
    let buffer = Bytes::<8>::new();
    assert_eq!(buffer.bytes, [0; 8]);
    assert_eq!(buffer.pointer, 0);

    let mut buffer = Bytes::<4>::new();
    buffer.push(0x7E);
    assert_eq!(buffer.bytes[0], 0x7E);
    assert_eq!(buffer.pointer, 1);

    buffer.push(0x01);
    buffer.push(0x02);
    buffer.push(0x03);
    assert_eq!(buffer.bytes, [0x7E, 0x01, 0x02, 0x03]);
    assert_eq!(buffer.pointer, 4);

    buffer.push(0x04);
    assert_eq!(buffer.bytes, [0x7E, 0x01, 0x02, 0x03]);
    assert_eq!(buffer.pointer, 4);

    let mut buffer = Bytes::<8>::new();
    buffer.extend(&[0x01, 0x02, 0x03]);
    assert_eq!(buffer.bytes[0..3], [0x01, 0x02, 0x03]);
    assert_eq!(buffer.pointer, 3);

    buffer.extend(&[0x04, 0x05]);
    assert_eq!(buffer.bytes[0..5], [0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(buffer.pointer, 5);

    buffer.extend(&[0x06, 0x07, 0x08, 0x09]);
    assert_eq!(buffer.bytes[0..5], [0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(buffer.pointer, 5);

    buffer.extend(&[]);
    assert_eq!(buffer.bytes[0..5], [0x01, 0x02, 0x03, 0x04, 0x05]);
    assert_eq!(buffer.pointer, 5);

    let buffer2 = buffer;
    assert_eq!(buffer.bytes, buffer2.bytes);
    assert_eq!(buffer.pointer, buffer2.pointer);

    let mut buffer = Bytes::<1>::new();
    buffer.push(0);
    buffer.push(0);

    buffer.extend(&[0, 0]);
}

#[test]
fn test_pid_parsing() {
    let test_cases = [
        (0x01, Pid::ISO8208),
        (0x06, Pid::RFC1144C),
        (0x07, Pid::RFC1144U),
        (0x08, Pid::SegFrag),
        (0xc3, Pid::TEXNET),
        (0xc4, Pid::LinkQuality),
        (0xca, Pid::AppleTalk),
        (0xcb, Pid::AppleTalkARP),
        (0xcc, Pid::ARPAIP),
        (0xcd, Pid::ARPAAR),
        (0xce, Pid::FlexNet),
        (0xcf, Pid::NETROM),
        (0xf0, Pid::NoL3),
        (0xff, Pid::EscChar),
    ];

    for (pid_byte, expected_pid) in test_cases {
        let mut packet = vec![0; 190];

        packet[0] = 0;
        packet[1..8].copy_from_slice(&[1, 1, 1, 1, 1, 1, 1]);
        packet[8..15].copy_from_slice(&[2, 2, 2, 2, 2, 2, 2]);
        packet[15] = 0b10101010;
        packet[16] = pid_byte;
        packet[17..188].fill(0);
        packet[188..190].copy_from_slice(&[0, 0]);

        let result = Fx25Fields::parse(&packet);

        assert_eq!(result.pid as u8, expected_pid as u8);
    }
}

#[test]
fn test_undefined_pid() {
    let mut packet = vec![0; 190];

    packet[0] = 0;
    packet[1..8].copy_from_slice(&[1, 1, 1, 1, 1, 1, 1]);
    packet[8..15].copy_from_slice(&[2, 2, 2, 2, 2, 2, 2]);
    packet[15] = 0b10101010;
    packet[16] = 0x00;
    packet[17..188].fill(0);
    packet[188..190].copy_from_slice(&[0, 0]);

    let result = Fx25Fields::parse(&packet);

    assert_eq!(result.pid as u8, Pid::NoL3 as u8);
}

#[test]
fn test_packet_too_short() {
    let short_packet = vec![0; 14];
    let _ = Fx25Fields::parse(&short_packet);
}

fn create_test_bytes(correlation_tag: &[u8], data: &[u8]) -> [u8; 271] {
    let mut bytes = [0u8; 271];
    bytes[4..12].copy_from_slice(correlation_tag);
    bytes[12..267].copy_from_slice(data);
    return bytes;
}

#[test]
fn test_invalid_correlation_tag() {
    let invalid_tag = [0xFF; 8];
    let data = [0; 255];
    let bytes = create_test_bytes(&invalid_tag, &data);

    let result = Packet::decode_fx25(bytes);
    assert!(result.is_err());
}

#[test]
fn test_invalid_crc() {
    let valid_tag = (CorrelationTag::Tag09 as u64).to_le_bytes();
    let valid_data = [0; 255];

    let mut bytes = create_test_bytes(&valid_tag, &valid_data);

    bytes[12] = 0;
    bytes[13..20].copy_from_slice(&[1, 1, 1, 1, 1, 1, 1]);
    bytes[20..27].copy_from_slice(&[2, 2, 2, 2, 2, 2, 2]);
    bytes[27] = 0b10101010;
    bytes[28] = 0x01;

    let result = Packet::decode_fx25(bytes);
    assert!(result.is_err());
}

#[test]
fn test_sframe_creation() {
    let test_cases = [
        (0, false, Supervisory::RR, 0b00000001),
        (7, true, Supervisory::RNR, 0b11110101),
        (3, true, Supervisory::REJ, 0b01111001),
        (5, false, Supervisory::SREJ, 0b10101101),
    ];

    for (recv_seq_num, poll_final, supervisory, expected_byte) in test_cases {
        let control = Control::new_sframe(recv_seq_num, poll_final, supervisory);

        assert_eq!(
            control.to_byte().unwrap(),
            expected_byte,
            "Control byte mismatch"
        );
        match control {
            Control::SFrame {
                recv_seq_num: r,
                poll_final: p,
                supervisory: s,
                byte: _,
            } => {
                assert_eq!(r, recv_seq_num, "Receive sequence number mismatch");
                assert_eq!(p, poll_final, "Poll/Final bit mismatch");
                assert_eq!(s, supervisory as u8, "Supervisory bits mismatch");
            }
            _ => panic!("Wrong Control variant returned"),
        }
    }
}

#[cfg(feature = "fuzz")]
mod fuzzing {
    use crate::gf;
    use crate::test::{sign_data, verify_data};
    use rand::{
        distributions::{Distribution, Standard},
        random, thread_rng, Rng, RngCore,
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
            Standard: Distribution<T>,
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

            to_parse[to_parse.len() - 3] = 0x7E;
            to_parse[to_parse.len() - 2] = 0;
            to_parse[to_parse.len() - 1] = 0;

            let parsed = ax25::frame::Ax25Frame::from_bytes(&to_parse[1..(to_parse.len())]);
            assert!(parsed.is_ok());

            let parsed = parsed.unwrap();

            assert_eq!(dest_callsign, parsed.destination.callsign.as_bytes());
            assert_eq!(source_callsign, parsed.source.callsign.as_bytes());

            let mut data_bytes = Bytes::<174>::new();
            data_bytes.extend(&data);
            data_bytes.push(0x7E);
            assert_eq!(Vec::from(data_bytes.bytes), parsed.to_bytes()[16..]);
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

    #[test]
    fn fuzz_sign_data() {
        let mut rng = thread_rng();

        for _ in 0..FUZZNUM {
            let data_len = rng.gen_range(0..2048);

            let mut data = vec![0u8; data_len as usize];
            rng.fill_bytes(&mut data);

            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);

            let signed = sign_data(&data, &key);

            assert_eq!(signed.len(), 50);
            assert!(verify_data(&data, signed, &key));

            let mut tampered = signed.clone();
            let tamper_pos = rng.gen_range(0..tampered.len());
            tampered[tamper_pos] ^= 0xFF;

            assert!(!verify_data(&data, tampered, &key));

            let mut wrong_key = key.clone();
            wrong_key[rng.gen_range(0..16)] ^= 0xFF;
            assert!(!verify_data(&data, signed, &wrong_key));
        }
    }

    #[test]
    fn fuzz_invalid_sign_data() {
        let mut rng = thread_rng();

        for _ in 0..FUZZNUM {
            let len = rng.gen_range(0..2048);
            let mut data = vec![0u8; len];
            rng.fill_bytes(&mut data);

            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);

            let mut signed = [0u8; 50];
            rng.fill_bytes(&mut signed);

            assert!(!verify_data(&data, signed, &key));
        }
    }
}
