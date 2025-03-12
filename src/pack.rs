//! # This module provides functionality for AX.25 and FX.25 packet encoding and decoding.
//!
//! AX.25 is an asynchronous link-layer protocol designed for amateur radio digital communications.
//! FX.25 is a forward error correction layer that wraps AX.25 frames with correlation tags and Reed-Solomon encoding.
//!
//! The main components in this module are:
//!
//! - `Address`: A structure representing AX.25 addresses (callsign + SSID)
//! - `Control`: An enum representing different types of AX.25 control fields (I-frames, S-frames, U-frames)
//! - `Pid`: An enum representing protocol identifiers for different L3 protocols
//! - `Packet`: The main structure for creating and decoding AX.25/FX.25 packets
//! - `CorrelationTag`: Unique identifiers for FX.25 frames indicating the Reed-Solomon encoding parameters
//!
//! ## Example
//! ```
//! use comms::pack::{Packet, Pid};
//!
//! // Create and encode an AX.25 packet
//! let packet = Packet::pack_to_ax25(
//!     *b"NOCALL",  // destination callsign
//!     *b"MYCALL",  // source callsign
//!     0,           // receive sequence number
//!     false,       // poll bit
//!     0,           // send sequence number
//!     Pid::NoL3,   // protocol ID
//!     [0; 171]     // payload data
//! );
//!
//! // Add FX.25 forward error correction
//! let fx25_frame = packet.pack_to_fx25();
//! ```

use crc_0x8810::update;
use reed_solomon::{Decoder, Encoder};

/// # A representation of an AX.25 address, consisting of a callsign and an SSID.
///
/// ## Arguments
/// - `callsign`: A `String` representing the station's callsign (up to 6 characters).
/// - `ssid`: An unsigned 8-bit integer representing the SSID. Only the lower 4 bits are used.
/// - `bytes`: A 7-byte array representing the encoded callsign and SSID in a format suitable for
///    AX.25 transmission. The first 6 bytes correspond to the callsign, and the 7th byte encodes the SSID
///    and control information.
///
/// ## Example
/// ```
/// use comms::pack::Address;
///
/// let addr = Address::new(*b"NOCALL", 0, true, false);
/// ```
pub struct Address {
    /// The station's callsign as a 6-byte array, with each byte left-shifted by 1
    pub callsign: [u8; 6],
    /// The SSID, using only the lower 4 bits (0-15)
    pub ssid: u8,
    /// The combined 7-byte array used for transmission, containing the encoded callsign and SSID
    pub bytes: [u8; 7],
}

impl Address {
    /// # A function to create an AX.25 adress from a callsign and an ssid.
    ///
    /// ## Arguments
    /// - `callsign`: A `String` representing the station's callsign (up to 6 characters)
    /// - `ssid`: A `u8` integer representing the SSID, only the first 4 bits are used therefore the ssid must be at most 15
    /// - `command`: A `bool` value indicating if the address is sending a command or a response
    /// - `last_addr`: A `bool` value indicating if the address is the last one in the list of receiver, repeaters and sender
    ///
    /// ## Example
    /// Here is an example on creating an address with the `callsign` 'NOCALL', the `ssid` of '0', sending a command and being either a repeater address or a receiver address.
    /// ```
    /// use comms::pack::Address;
    ///
    /// let addr = Address::new(*b"NOCALL", 0, true, false);
    /// ```
    pub fn new(mut callsign: [u8; 6], mut ssid: u8, command: bool, last_addr: bool) -> Self {
        ssid %= 16; // Make sure the SSID is within the valid range of 0-15

        for i in 0..callsign.len() {
            callsign[i] <<= 1;
        }

        let ssid_byte: u8 =
            (ssid << 1) | 0b01100000 | (last_addr as u8) | (((command ^ last_addr) as u8) << 7);

        let mut bytes: Bytes<7> = Bytes::<7>::new();
        bytes.extend(&callsign);
        bytes.push(ssid_byte);

        return Address {
            callsign,
            ssid,
            bytes: bytes.bytes,
        };
    }
}

/// # Supervisory frame types for AX.25 S-frames
///
/// Defines the four possible supervisory frame types that can be used in AX.25 S-frames.
/// These are used for flow control and error recovery functions.
///
/// The variants are represented as 2-bit values (00-11) in the control field.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Supervisory {
    /// Receive Ready - Indicates ready to receive more frames and acknowledges frames up to N(R)-1
    RR = 0b00,

    /// Receive Not Ready - Temporarily cannot accept additional I frames
    RNR = 0b01,

    /// Reject - Requests retransmission of I frames starting from N(R)
    REJ = 0b10,

    /// Selective Reject - Requests retransmission of only the specific I frame N(R)
    SREJ = 0b11,
}

/// # A representatoin of the `control` byte/bytes in an AX.25 packet
///
/// ## Arguments
/// The fields vary a lot between different types of frames, but each frame has at least the byte or bytes field which is used for the transmission of the frames. and the poll/final bool.
/// - `poll`/`poll_final`: A `bool` representing if the current packet requires an immediate reponse.
/// - `byte`(modulo 8): A `u8` containing the byte representation of the control field
/// - `bytes`(modulo 128): A `u8` array containing the byte representation of the control field
#[derive(Clone, Copy)]
pub enum Control {
    /// Information frame (I-frame) format that carries upper layer data
    IFrame {
        /// Receive sequence number N(R) - 3 bits indicating the sequence number of the next expected frame
        recv_seq_num: u8, // 3 bits
        /// Poll bit requesting immediate response from peer
        poll: bool, // 1 bit
        /// Send sequence number N(S) - 3 bits indicating this frame's sequence number
        send_seq_num: u8, // 3 bits
        /// Complete control byte constructed from the above fields
        byte: u8, // fully constructed i frame control byte
    },
    /// Supervisory frame (S-frame) format used for flow control and error recovery
    SFrame {
        /// Receive sequence number N(R) - 3 bits indicating the sequence number of the next expected frame
        recv_seq_num: u8, // 3 bits
        /// Poll/Final bit requesting or responding to immediate response
        poll_final: bool, // 1 bit
        /// Supervisory function bits defining frame type (RR, RNR, REJ, SREJ)
        supervisory: u8, // 2 bits
        /// Complete control byte constructed from the above fields
        byte: u8, // fully constructed s frame control byte
    },
    // /// Unnumbered frame (U-frame) format used for link management
    // UFrame {
    //     /// Frame modifier bits defining the specific U-frame type
    //     frame_mod: u8, // 5 bits
    //     /// Poll/Final bit requesting or responding to immediate response
    //     poll_final: bool, // 1 bit
    //     /// Complete control byte constructed from the above fields
    //     byte: u8, // fully constructed u frame control byte
    // },
    // IFrame128 { // FIXME: non functional because of fixed bytes length of packet
    //     recv_seq_num: u8, // 7 bits
    //     poll: bool,       // 1 bit
    //     send_seq_num: u8, // 7 bits
    //     bytes: [u8; 2],   // fully constructed i frame modulo 128 control bytes
    // },
    // SFrame128 {
    //     recv_seq_num: u8, // 7 bits
    //     poll_final: bool, // 1 bit
    //     supervisory: u8,  // 2 bits
    //     bytes: [u8; 2],   // fully constructed s frame modulo 128 control bytes
    // },
}

impl Control {
    /// # A function to create an IFrame AX.25 control field
    ///
    /// ## Arguments
    /// - `recv_seq_num`: The receive sequence number is a 3 bit integer. This number is the `send_seq_num` of the next frame to be received
    /// - `poll`: A `bool` used to determine if the command should be immediately reponded to
    /// - `send_seq_num`: The send sequence number is a 3 bit integer. This number represents the place of the packet in the sending/receiving order of the packets for assembly at reception
    ///
    /// ## Example
    /// Here is an example of a IFrame control field being created for a first packet in a communication that does not need an immediate response and the next packet will have the associated send sequence number of 1.
    /// ```
    /// use comms::pack::Control;
    ///
    /// let control = Control::new_iframe(1, false, 0);
    /// ```
    pub fn new_iframe(recv_seq_num: u8, poll: bool, send_seq_num: u8) -> Self {
        assert!(recv_seq_num < 8); // The receive sequence number must not be more than 7

        let poll_bit: u8 = poll as u8;

        let byte: u8 = (recv_seq_num << 5) | (poll_bit << 4) | (send_seq_num << 1) | 0b0;

        return Control::IFrame {
            recv_seq_num,
            poll,
            send_seq_num,
            byte,
        };
    }

    // TODO: check format of the example (specifically the supervisory function bits (section 4.2.1.2))

    /// # A function to create an SFrame AX.25 control field
    ///
    /// ## Arguments
    /// - `recv_seq_num`: The receive sequence number is a 3 bit integer. This number is the `send_seq_num` of the next frame to be received
    /// - `poll_final`: A `bool` used to determine if the command should be immediately reponded to
    /// - `supervisory`: The supervisory bit for the SFrame which has a maximum value of 3
    ///
    /// ## Example
    /// Here is an example of a SFrame control field being created for a first packet in a communication which is final.
    /// ```
    /// use comms::pack::{Control, Supervisory};
    ///
    /// let control = Control::new_sframe(1, true, Supervisory::RR);
    /// ```
    pub fn new_sframe(recv_seq_num: u8, poll_final: bool, supervisory: Supervisory) -> Self {
        assert!(recv_seq_num < 8); // The receive sequence number must not be more than 7

        let poll_final_bit: u8 = poll_final as u8;

        let byte: u8 =
            (recv_seq_num << 5) | (poll_final_bit << 4) | ((supervisory as u8) << 2) | 0b01;

        return Control::SFrame {
            recv_seq_num,
            poll_final,
            supervisory: supervisory as u8,
            byte,
        };
    }

    // /// # A function to create a UFrame AX.25 control field
    // ///
    // /// ## Arguments
    // /// - `frame_mod`: A `u8` representing the unnumbered frame modifier bits, this value must be less than 32
    // /// - `poll`(IFrame)/`poll_final`(SFrame, UFrame): A `bool` used to determine if the command should be immediately reponded to
    // ///
    // /// ## Example
    // /// Here is an example of a UFrame control field being created for an unnumbered frame that has a frame modifier of 0 and requires an immediate response
    // /// ```
    // /// use comms::pack::Control;
    // ///
    // /// let control = Control::new_uframe(0, true);
    // /// ```
    // pub fn new_uframe(frame_mod: u8, poll_final: bool) -> Self {
    //     assert!(frame_mod < 31, "The frame mod must not be more than 31");

    //     let poll_final_bit: u8 = poll_final as u8;

    //     let frame_mod_p1: u8 = frame_mod >> 2 << 2; // 3 bits
    //     let frame_mod_p2: u8 = frame_mod << 6 >> 6; // 2 bits

    //     let byte: u8 = (frame_mod_p1 << 5) | (poll_final_bit << 4) | (frame_mod_p2 << 2) | 0b11;

    //     return Control::UFrame {
    //         frame_mod,
    //         poll_final,
    //         byte,
    //     };
    // }

    // /// A function to create a modulo 128 IFrame AX.25 control field
    // ///
    // /// # Arguments
    // /// - `recv_seq_num`: The receive sequence number is a 7 bit integer. This number is the `send_seq_num` of the next frame to be received
    // /// - `poll`: A `bool` used to determine if the command should be immediately reponded to
    // /// - `send_seq_num`: The send sequence number is a 7 bit integer. This number represents the place within the sending order of packets this packet sits to help with assembly of packets at reception
    // ///
    // /// # Example
    // /// Here is an example of a modulo 128 IFrame control field being created for an informational frame that is the first packet being sent, does not require an immediate response and the next frame to be sent will have the send sequence number of 1
    // /// ```
    // /// let control = Control::new_iframe128(1, false, 0);
    // /// ```
    // fn new_iframe128(recv_seq_num: u8, poll: bool, send_seq_num: u8) -> Self {
    //     assert!(
    //         recv_seq_num < 128,
    //         "The receive sequence number must not be more than 127"
    //     );
    //     assert!(
    //         send_seq_num < 128,
    //         "The send sequence number must not be more than 127"
    //     );

    //     let poll_bit: u8 = poll as u8;

    //     let bytes: [u8; 2] = [(recv_seq_num << 1) | poll_bit, (send_seq_num << 1) | 0b0];

    //     return Control::IFrame128 {
    //         recv_seq_num: recv_seq_num,
    //         poll: poll,
    //         send_seq_num: send_seq_num,
    //         bytes: bytes,
    //     };
    // }

    // /// A function to create a modulo 128 SFrame AX.25 control field
    // ///
    // /// # Arguments
    // /// - `recv_seq_num`: The receive sequence number is a 7 bit integer. This number is the `send_seq_num` of the next frame to be received
    // /// - `poll_final`: A `bool` used to determine if the command should be immediately reponded to
    // /// - `supervisory`: The supervisory bit for the SFrame which has a maximum value of 3
    // ///
    // /// # Example
    // /// Here is an example of a SFrame control field being created for a first packet in a communication which is final.
    // /// ```
    // /// let control = Control::new_sframe(1, true, 0);
    // /// ```
    // fn new_sframe128(recv_seq_num: u8, poll_final: bool, supervisory: u8) -> Self {
    //     assert!(
    //         recv_seq_num < 128,
    //         "The receive sequence number must not be more than 127"
    //     );
    //     assert!(
    //         supervisory < 4,
    //         "The supervisory number must not be more than 3"
    //     );

    //     let poll_final_bit: u8 = poll_final as u8;

    //     let bytes: [u8; 2] = [
    //         (recv_seq_num << 1) | poll_final_bit,
    //         0b0000 | (supervisory << 2) | 0b01,
    //     ];

    //     return Control::SFrame128 {
    //         recv_seq_num: recv_seq_num,
    //         poll_final: poll_final,
    //         supervisory: supervisory,
    //         bytes: bytes,
    //     };
    // }

    /// # Returns the control byte for the Control enum variant
    ///
    /// ## Arguments
    /// * `self` - The Control enum variant
    ///
    /// ## Returns
    /// * `Some(u8)` - The control byte for the variant
    /// * `None` - If the control byte cannot be determined (never happens with current variants)
    pub fn to_byte(self: Self) -> Option<u8> {
        match self {
            Self::IFrame { byte, .. } => Some(byte),
            Self::SFrame { byte, .. } => Some(byte),
            // Self::UFrame { byte, .. } => Some(byte),
        }
    }
}

/// # A byte-adjacent structure representing the PID field to determine the L3 network protocol being used in the transmission.
///
/// ## Example
/// Here is an example creation of Pid byte.
/// ```
/// use comms::pack::Pid;
///
/// let pid = Pid::RFC1144C;
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Pid {
    /// ISO 8208/CCITT X.25 PLP protocol
    ISO8208 = 0x01,
    /// Compressed TCP/IP packet. Van Jacobson (RFC 1144)
    RFC1144C = 0x06,
    /// Uncompressed TCP/IP packet. Van Jacobson (RFC 1144)
    RFC1144U = 0x07,
    /// Segmentation fragment
    SegFrag = 0x08,
    /// TEXNET datagram protocol
    TEXNET = 0xC3,
    /// Link Quality Protocol
    LinkQuality = 0xC4,
    /// Appletalk protocol
    AppleTalk = 0xCA,
    /// Appletalk ARP
    AppleTalkARP = 0xCB,
    /// ARPA Internet Protocol
    ARPAIP = 0xCC,
    /// ARPA Address Resolution Protocol
    ARPAAR = 0xCD,
    /// FlexNet protocol
    FlexNet = 0xCE,
    /// NET/ROM protocol
    NETROM = 0xCF,
    /// No Layer 3 protocol
    NoL3 = 0xF0,
    /// Escape character
    EscChar = 0xFF,
}

/// # An AX.25 packet payload containing the information field data.
///
/// The payload has a fixed size of 171 bytes to maintain compatibility with FX.25 Reed-Solomon encoding.
/// Any unused bytes are padded with zeros.
pub struct Payload {
    /// The raw payload data bytes with a fixed length of 271 bytes.
    pub data: [u8; 171],
}

/// # A 64-bit correlation tag that identifies the Reed-Solomon encoding parameters for FX.25 frames.
///
/// The correlation tag is a unique 64-bit sequence that specifies parameters like the error check value size
/// and number of information bytes for a given Reed-Solomon encoding scheme.
///
/// Each variant represents a specific RS(n,k) encoding where:
/// - n is the total number of bytes after encoding
/// - k is the number of information bytes before encoding
/// - (n-k) is the number of check value bytes added
///
/// ## Example
/// ```
/// use comms::pack::CorrelationTag;
///
/// // Use RS(255,239) encoding with 16-byte check value
/// let tag = CorrelationTag::Tag01;
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum CorrelationTag {
    /// RS(255, 239) 16-byte check value, 239 information bytes
    Tag01 = 0xB74DB7DF8A532F3E,
    /// RS(144,128) - shortened RS(255, 239), 128 info bytes
    Tag02 = 0x26FF60A600CC8FDE,
    /// RS(80,64) - shortened RS(255, 239), 64 info bytes
    Tag03 = 0xC7DC0508F3D9B09E,
    /// RS(48,32) - shortened RS(255, 239), 32 info bytes
    Tag04 = 0x8F056EB4369660EE,
    /// RS(255, 223) 32-byte check value, 223 information bytes
    Tag05 = 0x6E260B1AC5835FAE,
    /// RS(160,128) - shortened RS(255, 223), 128 info bytes
    Tag06 = 0xFF94DC634F1CFF4E,
    /// RS(96,64) - shortened RS(255, 223), 64 info bytes
    Tag07 = 0x1EB7B9CDBC09C00E,
    /// RS(64,32) - shortened RS(255, 223), 32 info bytes
    Tag08 = 0xDBF869BD2DBB1776,
    /// RS(255, 191) 64-byte check value, 191 information bytes
    Tag09 = 0x3ADB0C13DEAE2836,
    /// RS(192, 128) - shortened RS(255, 191), 128 info bytes
    Tag0A = 0xAB69DB6A543188D6,
    /// RS(128, 64) - shortened RS(255, 191), 64 info bytes
    Tag0B = 0x4A4ABEC4A724B796,
}

impl CorrelationTag {
    fn to_bytes(&self) -> [u8; 8] {
        return (*self as u64).to_ne_bytes();
    }

    /// # A function to find bitwise the closest correlation tag
    ///
    /// This function using a hamming distance algorithm to determine the tag which is the closest to the valid tags.
    ///
    /// ## Exemple
    /// ```
    /// use comms::pack::CorrelationTag;
    /// let received_tag = &(0x4A4ABEC4A724B797u64).to_be_bytes();
    /// let tag = CorrelationTag::find_closest_tag(received_tag);
    /// ```
    pub fn find_closest_tag(received_bytes: &[u8]) -> CorrelationTag {
        let mut closest_tag = CorrelationTag::Tag09;
        let mut min_distance = u64::MAX;

        for tag in [
            CorrelationTag::Tag01,
            CorrelationTag::Tag02,
            CorrelationTag::Tag03,
            CorrelationTag::Tag04,
            CorrelationTag::Tag05,
            CorrelationTag::Tag06,
            CorrelationTag::Tag07,
            CorrelationTag::Tag08,
            CorrelationTag::Tag09,
            CorrelationTag::Tag0A,
            CorrelationTag::Tag0B,
        ] {
            match hamming_distance(&received_bytes, &tag.to_bytes()) {
                Some(distance) => {
                    if distance < min_distance {
                        min_distance = distance;
                        closest_tag = tag;
                    }
                }
                None => break,
            }
        }

        return closest_tag;
    }
}

fn hamming_distance(bytes1: &[u8], bytes2: &[u8]) -> Option<u64> {
    if bytes1.len() != bytes2.len() {
        return None;
    }

    let len = bytes1.len();
    let mut count = 0;

    for i in 0..len {
        if bytes1[i] != bytes2[i] {
            count += 1;
        }
    }

    return Some(count);
}

/// # Computes the CRC-16 value for a byte sequence using the polynomial 0x8810.
///
/// This function calculates a 16-bit Cyclic Redundancy Check (CRC) value for error detection
/// using the polynomial x^16 + x^12 + x^5 + 1 (0x8810). The CRC is computed by iterating
/// through the input bytes and updating a running CRC value.
///
/// ## Arguments
/// * `bytes` - A slice containing the sequence of bytes to compute the CRC for
///
/// ## Returns
/// * `u16` - The computed 16-bit CRC value
///
/// ## Example
/// ```
/// use comms::pack::compute_crc;
///
/// let data = [0x01, 0x02, 0x03];
/// let crc = compute_crc(&data);
/// ```
pub fn compute_crc(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;

    for &byte in bytes {
        let copy = byte;
        crc = update(crc, copy);
    }
    crc
}

/// # A fixed-length byte buffer with position tracking.
///
/// This struct provides a fixed-size byte array with a pointer to track the current position.
/// It is used internally for building AX.25 and FX.25 packet frames by sequentially adding bytes.
///
/// ## Arguments
/// * `bytes` - Fixed-size array to store the bytes
/// * `pointer` - Current position in the byte array
///
/// ## Example
/// ```
/// use comms::pack::Bytes;
///
/// let mut buffer = Bytes::<8>::new(); // Create 8-byte buffer
/// buffer.push(0x7E); // Add flag byte
/// buffer.extend(&[0x01, 0x02, 0x03]); // Add multiple bytes
/// ```
#[derive(Clone, Copy)]
pub struct Bytes<const N: usize> {
    /// Fixed-size byte array to store the sequence of bytes being built
    pub bytes: [u8; N],
    /// Current position/index in the byte array where the next byte will be written
    pub pointer: usize,
}

impl<const N: usize> Bytes<N> {
    /// # Creates a new empty Bytes buffer with specified size.
    ///
    /// Creates a new Bytes instance initialized with zeros and pointer at position 0.
    ///
    /// ## Example
    /// ```
    /// use comms::pack::Bytes;
    ///
    /// let mut buffer = Bytes::<8>::new(); // Create 8-byte buffer
    /// ```
    pub fn new() -> Bytes<N> {
        return Bytes {
            bytes: [0; N],
            pointer: 0,
        };
    }

    /// # Appends a single byte to the Bytes buffer.
    ///
    /// Adds a byte to the buffer at the current pointer position if there is room.
    /// The pointer is advanced if the byte is successfully added.
    /// Returns silently without modifying buffer if at capacity.
    ///
    /// ## Arguments
    /// * `value` - The byte value to append to the buffer
    ///
    /// ## Example
    /// ```
    /// use comms::pack::Bytes;
    ///
    /// let mut buffer = Bytes::<8>::new();
    /// buffer.push(0x7E); // Add flag byte
    /// ```
    pub fn push(&mut self, value: u8) {
        if self.pointer >= self.bytes.len() {
            return;
        }

        self.bytes[self.pointer] = value;

        self.pointer += 1;
    }

    /// # Extends the Bytes buffer by appending multiple bytes.
    ///
    /// Adds a sequence of bytes from a slice to the buffer at the current pointer position.
    /// The pointer is advanced for each byte added. Returns silently without modification if
    /// adding all bytes would exceed capacity.
    ///
    /// ## Arguments
    /// * `values` - Slice containing the bytes to append to the buffer
    ///
    /// ## Example
    /// ```
    /// use comms::pack::Bytes;
    ///
    /// let mut buffer = Bytes::<8>::new();
    /// buffer.extend(&[0x01, 0x02, 0x03]); // Add multiple bytes
    /// ```
    pub fn extend(&mut self, values: &[u8]) {
        if values.len() + self.pointer >= self.bytes.len() {
            return;
            // unreachable!("Values added to bytes must fit in the bytes object.");
        }

        for value in values {
            self.push(*value);
        }
    }
}

/// # A structure representing an AX.25/FX.25 packet with addressing, control, and payload data.
///
/// The Packet structure contains all the components needed to construct or parse a complete
/// AX.25 or FX.25 frame, including:
///
/// ## Example
/// ```
/// use comms::pack::{Packet, Pid};
///
/// let packet = Packet::pack_to_ax25(
///     *b"NOCALL",  // Destination callsign
///     *b"MYCALL",  // Source callsign
///     0,           // Receive sequence number
///     false,       // Poll bit
///     0,           // Send sequence number
///     Pid::NoL3,   // Protocol ID
///     [0; 171]     // Payload data
/// );
/// ```
pub struct Packet {
    /// Destination station address containing callsign and SSID
    pub dest_addr: Address,
    /// Source station address containing callsign and SSID
    pub source_addr: Address,
    /// Control field indicating frame type and sequence numbers
    pub control: Control,
    /// Protocol identifier for the Layer 3 protocol
    pub pid: Pid,
    /// Information field data
    pub payload: Payload,
    /// Complete raw packet bytes including flags and FCS
    pub bytes: [u8; 191],
}

impl Packet {
    /// # Encodes a packet as an AX.25 frame.
    ///
    /// This function takes the individual components of an AX.25 packet and assembles them into a complete frame
    /// including address fields, control field, protocol ID, payload data and CRC.
    ///
    /// ## Arguments
    /// * `dest_callsign` - 6-byte array containing the destination callsign
    /// * `source_callsign` - 6-byte array containing the source callsign
    /// * `recv_seq_num` - Receive sequence number (0-7)
    /// * `poll` - Poll bit indicating if immediate response is required
    /// * `send_seq_num` - Send sequence number (0-7)
    /// * `pid` - Protocol identifier indicating Layer 3 protocol
    /// * `data` - 171-byte array containing the payload data
    ///
    /// ## Returns
    /// A new Packet struct containing the assembled frame
    ///
    /// ## Example
    /// ```
    /// use comms::pack::{Packet, Pid};
    ///
    /// let packet = Packet::pack_to_ax25(
    ///     *b"NOCALL",  // Destination callsign
    ///     *b"MYCALL",  // Source callsign
    ///     0,           // Receive sequence number
    ///     false,       // Poll bit
    ///     0,           // Send sequence number
    ///     Pid::NoL3,   // Protocol ID
    ///     [0; 171]     // Payload data
    /// );
    /// ```
    pub fn pack_to_ax25(
        dest_callsign: [u8; 6],
        source_callsign: [u8; 6],
        recv_seq_num: u8,
        poll: bool,
        send_seq_num: u8,
        pid: Pid,
        data: [u8; 171],
    ) -> Packet {
        let dest_addr: Address = Address::new(dest_callsign, 0, true, false);
        let source_addr: Address = Address::new(source_callsign, 0, true, true);

        let control: Control = Control::new_iframe(recv_seq_num, poll, send_seq_num);

        let payload: Payload = Payload { data };

        let crc = compute_crc(&payload.data).to_be_bytes();

        let mut bytes: Bytes<191> = Bytes::<191>::new();

        bytes.push(0x7E); // AX.25 opening flag
        bytes.extend(&dest_addr.bytes);
        bytes.extend(&source_addr.bytes);

        bytes.push(control.to_byte().unwrap());

        bytes.push(pid as u8);
        bytes.extend(&payload.data);
        bytes.extend(&crc);
        bytes.push(0x7E); // AX.25 closing flag

        let packet = Packet {
            dest_addr,
            source_addr,
            control,
            pid,
            payload,
            bytes: bytes.bytes,
        };

        return packet;
    }

    /// # Encodes an existing AX.25 packet as an FX.25 frame with error correction.
    ///
    /// This function takes an AX.25 packet and wraps it with FX.25 framing, including:
    /// - Opening flags
    /// - Correlation tag indicating Reed-Solomon encoding parameters
    /// - Reed-Solomon error correction coding
    /// - Closing flags
    ///
    /// The FX.25 frame uses a 64-byte check value size with Reed-Solomon RS(255,191) encoding.
    ///
    /// ## Returns
    /// * `[u8; 271]` - The complete encoded FX.25 frame as a fixed-size byte array
    ///
    /// ## Example
    /// ```
    /// use comms::pack::{Packet, Pid};
    ///
    /// let ax25_packet = Packet::pack_to_ax25(
    ///     *b"NOCALL",  // Destination callsign
    ///     *b"MYCALL",  // Source callsign
    ///     0,           // Receive sequence number
    ///     false,       // Poll bit
    ///     0,           // Send sequence number
    ///     Pid::NoL3,   // Protocol ID
    ///     [0; 171]     // Payload data
    /// );
    ///
    /// let fx25_frame = ax25_packet.pack_to_fx25();
    /// ```
    pub fn pack_to_fx25(self: Self) -> [u8; 271] {
        let mut bytes: Bytes<271> = Bytes::<271>::new();

        bytes.push(0x7E); // FX.25 Opening flags
        bytes.push(0x7E);
        bytes.push(0x7E);
        bytes.push(0x7E);

        bytes.extend(&CorrelationTag::Tag09.to_bytes());

        let ecc_len = 64;
        let encoder = Encoder::new(ecc_len);

        let encoded = encoder.encode(&self.bytes);
        bytes.extend(&encoded[..]);

        bytes.push(0x7E); // FX.25 Closing flags
        bytes.push(0x7E);
        bytes.push(0x7E);
        bytes.push(0xFE);

        return bytes.bytes;
    }

    /// # Decodes an FX.25 frame and extracts the contained AX.25 packet.
    ///
    /// This function takes a complete FX.25 frame and:
    /// - Validates the correlation tag matches RS(255,191) parameters
    /// - Performs Reed-Solomon error correction decoding
    /// - Extracts and validates packet fields (addresses, control, PID, payload)
    /// - Verifies CRC matches payload
    ///
    /// ## Arguments
    /// * `bytes` - Complete 271-byte FX.25 frame to decode
    ///
    /// ## Returns
    /// * `Ok(Packet)` - Successfully decoded AX.25 packet
    /// * `Err(())` - Frame could not be decoded due to invalid format or uncorrectable errors
    ///
    /// ## Example
    /// ```
    /// use comms::pack::Packet;
    ///
    /// let fx25_frame = [0u8; 271]; // Received FX.25 frame
    /// match Packet::decode_fx25(fx25_frame) {
    ///     Ok(packet) => {
    ///         // Process decoded AX.25 packet
    ///     },
    ///     Err(_) => {
    ///         // Handle decoding error
    ///     }
    /// }
    /// ```
    pub fn decode_fx25(bytes: [u8; 271]) -> Result<Packet, ()> {
        let ecc_len = 64;
        let decoder = Decoder::new(ecc_len);

        let correlation_tag = CorrelationTag::find_closest_tag(&bytes[4..12]);
        if correlation_tag as u64 != CorrelationTag::Tag09 as u64 {
            return Err(());
        }

        let known_errors = [0];
        let decoded = decoder.correct(&bytes[12..267], Some(&known_errors));

        if decoded.is_err() {
            return Err(());
        }

        let fields = Fx25Fields::parse(decoded.unwrap().data());
        let dest_callsign = fields.dest_callsign;
        let source_callsign = fields.source_callsign;
        let recv_seq_num = fields.recv_seq_num;
        let poll = fields.poll;
        let send_seq_num = fields.send_seq_num;
        let pid = fields.pid;
        let data = fields.data;
        let decoded_crc = fields.crc;

        let mut dest_callsign_bytes: [u8; 6] = [0; 6];
        dest_callsign_bytes.copy_from_slice(&dest_callsign[0..6]);
        for i in 0..6 {
            dest_callsign_bytes[i] >>= 1;
        }

        let dest_addr = Address {
            callsign: dest_callsign_bytes,
            ssid: dest_callsign[6],
            bytes: dest_callsign,
        };

        let mut source_callsign_bytes: [u8; 6] = [0; 6];
        source_callsign_bytes.copy_from_slice(&source_callsign[0..6]);
        for i in 0..6 {
            source_callsign_bytes[i] >>= 1;
        }

        let source_addr = Address {
            callsign: source_callsign_bytes,
            ssid: source_callsign[6],
            bytes: source_callsign,
        };

        let payload = Payload { data };

        // Check data with CRC
        let crc = compute_crc(&data);
        if crc.to_be_bytes() != decoded_crc {
            return Err(());
        }

        let mut bytes: [u8; 191] = [0; 191];
        bytes.copy_from_slice(decoded.unwrap().data());

        let control = Control::new_iframe(recv_seq_num, poll, send_seq_num);

        let packet = Packet {
            dest_addr,
            source_addr,
            control,
            pid,
            payload,
            bytes,
        };

        return Ok(packet);
    }
}

/// # A structure containing the core fields of an FX.25 frame after decoding.
///
/// This structure holds the individual components extracted from a decoded FX.25 frame,
/// including addressing information, sequence numbers, and payload data. It represents
/// the intermediate step between raw FX.25 bytes and a fully constructed AX.25 packet.
///
/// ## Example
/// ```
/// use comms::pack::Fx25Fields;
///
/// let frame_bytes = [0u8; 271]; // Received FX.25 frame
///
/// let fields = Fx25Fields::parse(&frame_bytes);
/// let source = fields.source_callsign;
/// let dest = fields.dest_callsign;
/// let data = fields.data;
/// ```
pub struct Fx25Fields {
    /// 7-byte array containing the source station's callsign and SSID
    pub source_callsign: [u8; 7],
    /// 7-byte array containing the destination station's callsign and SSID
    pub dest_callsign: [u8; 7],
    /// Receive sequence number N(R) from control field
    pub recv_seq_num: u8,
    /// Poll/Final bit from the control field
    pub poll: bool,
    /// Send sequence number N(S) from control field
    pub send_seq_num: u8,
    /// Protocol identifier indicating Layer 3 protocol
    pub pid: Pid,
    /// 171-byte array containing information field payload
    pub data: [u8; 171],
    /// 2-byte array containing frame check sequence
    pub crc: [u8; 2],
}

impl Fx25Fields {
    /// # Parses raw packet bytes into FX.25 frame fields.
    ///
    /// Takes a byte slice of an FX.25 frame and extracts the individual components:
    /// - Address fields (source and destination callsigns/SSIDs)
    /// - Control field bits (sequence numbers, poll bit)
    /// - Protocol ID
    /// - Payload data
    /// - CRC check value
    ///
    /// ## Arguments
    /// * `packet` - Byte slice containing complete FX.25 frame data
    ///
    /// ## Returns
    /// * `Some(Fx25Fields)` - Successfully parsed frame fields
    /// * `None` - Frame could not be parsed due to invalid length or format
    ///
    /// ## Example
    /// ```
    /// use comms::pack::Fx25Fields;
    ///
    /// let frame_bytes = [0u8; 271]; // Received FX.25 frame
    ///
    /// let fields = Fx25Fields::parse(&frame_bytes);
    /// let dest = fields.dest_callsign;
    /// let source = fields.source_callsign;
    /// let data = fields.data;
    /// ```
    pub fn parse(mut packet: &[u8]) -> Self {
        if packet.len() < 15 {
            packet = &[0u8; 271];
        }

        let mut dest = [0u8; 7];
        let mut source = [0u8; 7];

        dest.copy_from_slice(&packet[1..8]);
        source.copy_from_slice(&packet[8..15]);

        let control = packet[15];

        let recv_seq_num = (control >> 5) & 0x07; // N(R) is bits 5-7
        let poll = (control & 0x10) != 0; // P/F is bit 4
        let send_seq_num = (control >> 1) & 0x07; // N(S) is bits 1-3

        let pid = match packet[16] {
            0x01 => Pid::ISO8208,
            0x06 => Pid::RFC1144C,
            0x07 => Pid::RFC1144U,
            0x08 => Pid::SegFrag,
            0xc3 => Pid::TEXNET,
            0xc4 => Pid::LinkQuality,
            0xca => Pid::AppleTalk,
            0xcb => Pid::AppleTalkARP,
            0xcc => Pid::ARPAIP,
            0xcd => Pid::ARPAAR,
            0xce => Pid::FlexNet,
            0xcf => Pid::NETROM,
            0xf0 => Pid::NoL3,
            0xff => Pid::EscChar,
            _ => Pid::NoL3,
        };

        let mut data: [u8; 171] = [0; 171];
        data.copy_from_slice(&packet[17..188]);

        let mut crc: [u8; 2] = [0; 2];
        crc.copy_from_slice(&packet[188..190]);

        return Fx25Fields {
            dest_callsign: dest,
            source_callsign: source,
            recv_seq_num,
            poll,
            send_seq_num,
            pid,
            data,
            crc,
        };
    }
}
