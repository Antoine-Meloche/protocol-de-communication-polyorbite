#[cfg(not(feature = "cubesat"))]
use comms::pack::{Packet, Pid};

#[cfg(not(feature = "cubesat"))]
fn main() {
    let mut data = [0u8; 171];
    data.copy_from_slice("Hello world!".as_bytes());

    let ax25_packet: Packet =
        Packet::pack_to_ax25(*b"HFU4D ", *b"IUJDH8", 1, true, 2, Pid::NoL3, data);

    println!("{:?}", ax25_packet.bytes);

    let fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

    println!("{:?}", fx25_bytes);

    let decoded_bytes = Packet::decode_fx25(fx25_bytes);

    println!("{:?}", decoded_bytes.unwrap().bytes);
}

#[cfg(feature = "cubesat")]
use comms::{cubesat::load_to_transmit, pack::Packet};

#[cfg(feature = "cubesat")]
fn main() {
    let data_str = *b"Hello World!";
    let mut data = [0u8; 171];
    data[..data_str.len()].copy_from_slice(&data_str);

    let fx25_bytes: [u8; 271] = load_to_transmit(*b"HFU4D ", *b"IUJDH8", data);

    println!("{:?}", fx25_bytes);

    let decoded_packet = Packet::decode_fx25(fx25_bytes).unwrap();

    println!("{:?}", decoded_packet.bytes);
}
