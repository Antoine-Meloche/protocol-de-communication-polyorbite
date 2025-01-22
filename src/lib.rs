#![cfg_attr(not(feature = "ground-station"), no_std)]

pub mod gf;
pub mod pack;

extern crate reed_solomon;

#[cfg(feature = "ground-station")]
mod ground_station {
    use crate::pack::{Packet, Pid};

    const SOURCE_CALLSIGN: [u8; 6] = *b"HFG5  ";

    pub fn send_data(dest_callsign: [u8; 6], data: [u8; 171]) {
        let ax25_packet: Packet =
            Packet::pack_to_ax25(dest_callsign, SOURCE_CALLSIGN, 1, true, 2, Pid::NoL3, data);
        let fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

        println!("{:?}", fx25_bytes); // FIXME: replace with sending logic
    }
}

#[cfg(feature = "ground-station")]
#[cfg(test)]
mod test;

#[cfg(feature = "cubesat")]
pub mod cubesat {
    use crate::pack::{Packet, Pid};

    pub fn load_to_transmit(dest_callsign: &str, source_callsign: &str, data: &str) -> [u8; 271] {
        let ax25_packet: Packet =
            Packet::pack_to_ax25(dest_callsign, source_callsign, 1, true, 2, Pid::NoL3, data);
        let fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

        return fx25_bytes;
    }
}
