use comms::pack::{Packet, Pid};

fn main() {
    let start = std::time::Instant::now();
    let duration = std::time::Duration::from_secs(1);
    let mut packets = 0;

    // Pre-allocate buffers
    const BUFFER_SIZE: usize = 171;
    let mut data_buffer = [0u8; BUFFER_SIZE];
    let hello_bytes = b"hello world";
    data_buffer[..hello_bytes.len()].copy_from_slice(hello_bytes);

    loop {
        if start.elapsed() >= duration {
            break;
        }

        let dest_callsign = *b"nj7p  ";
        let source_callsign = *b"n7lem ";
        let recv_seq_num = 1;
        let poll = true;
        let send_seq_num = 2;
        let pid = Pid::NoL3;

        let packet = Packet::pack_to_ax25(
            dest_callsign,
            source_callsign,
            recv_seq_num,
            poll,
            send_seq_num,
            pid,
            data_buffer,
        );
        let fx25_packet = packet.pack_to_fx25();
        if let Ok(_decoded) = Packet::decode_fx25(fx25_packet) {
            packets += 1;
        }
    }

    println!("{} packets/second", packets);
    print_throughput(packets);
}

fn print_throughput(packets: u32) {
    let bytes = packets as u64 * 271;
    match () {
        _ if bytes >= 1_000_000 => println!("{:.2} mb/s", bytes as f64 / 1_000_000.0),
        _ if bytes >= 1_000 => println!("{:.2} kb/s", bytes as f64 / 1_000.0),
        _ => println!("{:.2} b/s", bytes as f64),
    }
}
