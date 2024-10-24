use pack::{Packet, Pid};
use utils::str_to_6_u8_array;

use super::*;

#[test]
fn test_str_to_6_u8_array() {
    let expected_output: [u8; 6] = [156, 148, 110, 160, 64, 64];
    let actual_output: [u8; 6] = str_to_6_u8_array("NJ7P");

    assert_eq!(actual_output, expected_output);
}

#[test]
fn test_ax25_pack() {
    let expected_output: [u8; 27] = [156, 148, 110, 160, 64, 64, 224, 156, 110, 152, 138, 154, 64, 97, 52, 240, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
    let actual_output: Vec<u8> = Packet::pack_to_ax25("NJ7P", "N7LEM", 1, true, 2, Pid::NoL3, "Hello world").bytes;

    assert_eq!(actual_output, expected_output);
}