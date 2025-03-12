//! # A library for the communication protocol use in PolyOrbite's CubeSat based on AX.25 & FX.25
//!
//! This library provides functionality for:
//! - Packing data into AX.25 packets
//! - Converting AX.25 packets to FX.25 format
//! - Signing data packets for verification using ASCON encryption as well as md5 hashes and a CRC
//! - Ground station and CubeSat communication features
//!
//! The library supports both no_std environments (for CubeSat use) and
//! standard environments with the "ground-station" feature enabled.

#![cfg_attr(not(feature = "ground-station"), no_std)]
#![warn(missing_docs)]

pub mod gf;
pub mod pack;
pub mod sign;

extern crate reed_solomon;

/// # Provides functions for sending data packets from a ground station.
///
/// Handles taking payload bytes, packing them into AX.25 packets,
/// converting to FX.25 format, and sending to the CubeSat.
///
/// ## Example
/// ```
/// use comms::ground_station::send_data;
///
/// let dest = *b"CUBES1";
/// let data = [0u8; 171];
/// send_data(dest, &data);
/// ```
#[cfg(feature = "ground-station")]
pub mod ground_station {
    use crate::{
        pack::{Packet, Pid},
        sign::sign_data,
    };

    const SOURCE_CALLSIGN: [u8; 6] = *b"HFG5  ";

    /// # Package data into FX.25 frames and send them to a ground destination.
    /// First breaks data into packets of 171 bytes, adds sequence numbers,
    /// converts to AX.25 packets, then FX.25 frames. Handles signing the
    /// data with a hardcoded key.
    ///
    /// ## Arguments
    /// * `dest_callsign` - Callsign of destination ground station (6 bytes)
    /// * `data` - Data bytes to send
    ///
    /// ## Examples
    /// ```
    /// use comms::ground_station::send_data;
    ///
    /// let dest = *b"CUBES1";
    /// let mut data = [0u8; 171];
    /// data[0..14].copy_from_slice(b"Hello CubeSat!");
    /// send_data(dest, &data);
    /// ```
    pub fn send_data(dest_callsign: [u8; 6], data: &[u8]) {
        let packet_count: usize = (data.len() + 170) / 171;

        for i in 0..packet_count {
            let recv_seq_num = (i % 8) as u8;
            let send_seq_num = ((i + 1) % 8) as u8;

            let mut packet_data = [0u8; 171];
            let start = i * 171;
            let end = core::cmp::min(start + 171, data.len());

            if start < data.len() {
                packet_data[..(end - start)].copy_from_slice(&data[start..end]);
            }

            let ax25_packet: Packet = Packet::pack_to_ax25(
                dest_callsign,
                SOURCE_CALLSIGN,
                recv_seq_num,
                false,
                send_seq_num,
                Pid::NoL3,
                packet_data,
            );
            let fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

            println!("{:?}", fx25_bytes); // FIXME: replace with sending logic
        }

        let recv_seq_num = (packet_count % 8) as u8;
        let send_seq_num = 0u8;

        let mut packet_data = [0u8; 171];

        let key_raw = b"0123456789abcdef"; // FIXME: replace with hardcoded private key
        let verif = sign_data(data, key_raw);
        packet_data[..50].copy_from_slice(&verif);

        let ax25_packet: Packet = Packet::pack_to_ax25(
            dest_callsign,
            SOURCE_CALLSIGN,
            recv_seq_num,
            true,
            send_seq_num,
            Pid::NoL3,
            packet_data,
        );

        let fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

        println!("{:?}", fx25_bytes); // FIXME: replace with sending logic
    }
}

#[cfg(feature = "ground-station")]
#[cfg(test)]
mod test;

/// # Provides functions for handling on-board CubeSat communication.
///
/// Contains functionality for:
/// - Loading packets into the radio buffer for transmission
/// - Processing received ground station commands
/// - Verifying packet signatures and CRCs
/// - Tracking communication stats
///
/// ## Example
/// ```
/// let dest = *b"GROUND";
/// let source = *b"SATID1";
/// let data = [0u8; 171];
/// let tx_packet = load_to_transmit(dest, source, data);
/// ```
#[cfg(feature = "cubesat")]
pub mod cubesat {
    use crate::pack::{Packet, Pid};

    const SOURCE_CALLSIGN: [u8; 6] = [12, 12, 12, 43, 43, 56];

    /// # Package data into FX.25 frame for radio transmission.
    /// Takes destination and source callsigns along with payload data and creates an
    /// FX.25 frame that can be loaded into the radio buffer for transmission.
    ///
    /// ## Arguments
    /// * `dest_callsign` - Destination callsign (6 bytes)
    /// * `source_callsign` - Source callsign (6 bytes)
    /// * `data` - 171 byte payload to transmit
    ///
    /// ## Returns
    /// * FX.25 frame as 271 byte array
    ///
    /// ## Examples
    /// ```
    /// let dest = *b"GROUND";
    /// let source = *b"CUBES1";
    /// let data = [0u8; 171];
    /// let tx_frame = load_to_transmit(dest, source, data);
    /// ```
    pub fn load_to_transmit(dest_callsign: [u8; 6], data: &[u8]) -> [u8; 271] {
        let packet_count: usize = (data.len() + 170) / 171;

        for i in 0..packet_count {
            let recv_seq_num = (i % 8) as u8;
            let send_seq_num = ((i + 1) % 8) as u8;

            let mut packet_data = [0u8; 171];
            let start = i * 171;
            let end = core::cmp::min(start + 171, data.len());

            if start < data.len() {
                packet_data[..(end - start)].copy_from_slice(&data[start..end]);
            }

            let ax25_packet: Packet = Packet::pack_to_ax25(
                dest_callsign,
                SOURCE_CALLSIGN,
                recv_seq_num,
                i == packet_count,
                send_seq_num,
                Pid::NoL3,
                packet_data,
            );
            let _fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

            // FIXME: Add sending logic
        }

        return [0u8; 271];
    }
}
