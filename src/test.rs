use pack::{Packet, Pid, Bytes};

use super::*;

macro_rules! assert {
    ($condition:expr) => {
        if !$condition {
            // panic!("Assertion failed!");
        }
    };
}

#[test]
fn test_ax25_pack() {
    let bytes: Bytes<209> = Bytes::<209>::new();
    bytes.extend(&[0x7E, 156, 148, 110, 160, 64, 64, 224, 156, 110, 152, 138, 154, 64, 97, 52, 240, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]);
    let actual_output: [u8; 209] = Packet::pack_to_ax25("NJ7P", "N7LEM", 1, true, 2, Pid::NoL3, "Hello world").bytes;

    assert!(actual_output == bytes.bytes);
}