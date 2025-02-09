#![cfg_attr(not(feature = "ground-station"), no_std)]

pub mod gf;
pub mod pack;
pub mod sign;

extern crate reed_solomon;

#[cfg(feature = "ground-station")]
mod ground_station {
    use crate::{
        pack::{Packet, Pid},
        sign::sign_data,
    };

    const SOURCE_CALLSIGN: [u8; 6] = *b"HFG5  ";

    pub fn send_data(dest_callsign: [u8; 6], data: &[u8]) {
        let packet_count: usize = data.len() / 171 + 1;

        for i in 0..packet_count {
            let recv_seq_num = (i % 8) as u8;
            let send_seq_num = ((i + 1) % 8) as u8;

            let mut packet_data = [0u8; 171];
            packet_data.copy_from_slice(&data[(171 * i)..(171 * (i + 1))]);

            let ax25_packet: Packet = Packet::pack_to_ax25(
                dest_callsign,
                SOURCE_CALLSIGN,
                recv_seq_num,
                i == packet_count - 1, // Poll bit true when last packet of command
                send_seq_num,
                Pid::NoL3,
                packet_data,
            );
            let fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

            println!("{:?}", fx25_bytes); // FIXME: replace with sending logid
        }

        let recv_seq_num = (packet_count % 8) as u8;
        let send_seq_num = 0u8;

        let mut packet_data = [0u8; 171];

        let key_raw = b"0123456789abcdef"; // FIXME: replace with hardcoded private key
        let verif = sign_data(data, key_raw);
    }
}

#[cfg(feature = "ground-station")]
#[cfg(test)]
mod test;

#[cfg(feature = "cubesat")]
pub mod cubesat {
    use crate::pack::{Packet, Pid};

    pub fn load_to_transmit(
        dest_callsign: [u8; 6],
        source_callsign: [u8; 6],
        data: [u8; 171],
    ) -> [u8; 271] {
        let ax25_packet: Packet =
            Packet::pack_to_ax25(dest_callsign, source_callsign, 1, true, 2, Pid::NoL3, data);
        let fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

        return fx25_bytes;
    }
}
