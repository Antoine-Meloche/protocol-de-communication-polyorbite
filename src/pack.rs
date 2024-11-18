// use crate::reed_solomon::ReedSolomon;

/// A representation of an AX.25 address, consisting of a callsign and an SSID.
/// 
/// # Fields
/// - `callsign`: A `String` representing the station's callsign (up to 6 characters).
/// - `ssid`: An unsigned 8-bit integer representing the SSID. Only the lower 4 bits are used.
/// - `bytes`: A 7-byte array representing the encoded callsign and SSID in a format suitable for
///    AX.25 transmission. The first 6 bytes correspond to the callsign, and the 7th byte encodes the SSID
///    and control information.
/// 
/// # Example
/// ```
/// use comms::pack::Address;
/// 
/// let addr = Address::new("NOCALL", 0, true, false);
/// ```
pub struct Address<'a> {
    pub callsign: &'a str,
    pub ssid: u8, // MAX 4 bits
    pub bytes: [u8; 7],
}

impl<'a> Address<'a> {
    /// A function to create an AX.25 adress from a callsign and an ssid.
    /// 
    /// # Fields
    /// - `callsign`: A `String` representing the station's callsign (up to 6 characters)
    /// - `ssid`: A `u8` integer representing the SSID, only the first 4 bits are used therefore the ssid must be at most 15
    /// - `command`: A `bool` value indicating if the address is sending a command or a response
    /// - `last_addr`: A `bool` value indicating if the address is the last one in the list of receiver, repeaters and sender
    /// 
    /// # Example
    /// Here is an example on creating an address with the `callsign` 'NOCALL', the `ssid` of '0', sending a command and being either a repeater address or a receiver address.
    /// ```
    /// use comms::pack::Address;
    /// 
    /// let addr = Address::new("NOCALL", 0, true, false);
    /// ```
    pub fn new(callsign: &'a str, ssid: u8, command: bool, last_addr: bool) -> Self {
        if callsign.chars().count() > 6 {
            // panic!("The callsign cannot be longer than 6 characters"); // FIXME: remove panic!
        }

        if ssid > 15 {
            // panic!(
            //     "The destination SSID is larger than the allowed amount (15): {} > 15",
            //     ssid
            // ); // FIXME: remove panic!
        }

        let mut callsign_bytes: [u8; 6] = [32; 6];
        for (i, char) in callsign.chars().enumerate() {
            callsign_bytes[i] = char as u8;
        }

        for i in 0..callsign_bytes.len() {
            callsign_bytes[i] <<= 1;
        }

        let ssid_byte: u8 = (ssid << 1)
            | 0b01100000
            | (last_addr as u8)
            | (((command ^ last_addr) as u8) << 7);

        let mut bytes: Bytes<7> = Bytes::<7>::new();
        bytes.extend(&callsign_bytes);
        bytes.push(ssid_byte);

        return Address {
            callsign: callsign,
            ssid: ssid,
            bytes: bytes.bytes,
        };
    }
}

/// A representatoin of the `control` byte/bytes in an AX.25 packet
/// 
/// # Fields
/// The fields vary a lot between different types of frames, but each frame has at least the byte or bytes field which is used for the transmission of the frames. and the poll/final bool.
/// - `poll`/`poll_final`: A `bool` representing if the current packet requires an immediate reponse.
/// - `byte`(modulo 8): A `u8` containing the byte representation of the control field
/// - `bytes`(modulo 128): A `u8` array containing the byte representation of the control field
pub enum Control {
    IFrame {
        recv_seq_num: u8, // 3 bits
        poll: bool,       // 1 bit
        send_seq_num: u8, // 3 bits
        byte: u8,         // fully constructed i frame control byte
    },
    SFrame {
        recv_seq_num: u8, // 3 bits
        poll_final: bool, // 1 bit
        supervisory: u8,  // 2 bits
        byte: u8,         // fully constructed s frame control byte
    },
    UFrame {
        frame_mod: u8,    // 5 bits
        poll_final: bool, // 1 bit
        byte: u8,         // fully constructed u frame control byte
    },

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
    /// A function to create an IFrame AX.25 control field
    /// 
    /// # Fields
    /// - `recv_seq_num`: The receive sequence number is a 3 bit integer. This number is the `send_seq_num` of the next frame to be received
    /// - `poll`: A `bool` used to determine if the command should be immediately reponded to
    /// - `send_seq_num`: The send sequence number is a 3 bit integer. This number represents the place of the packet in the sending/receiving order of the packets for assembly at reception
    /// 
    /// # Example
    /// Here is an example of a IFrame control field being created for a first packet in a communication that does not need an immediate response and the next packet will have the associated send sequence number of 1.
    /// ```
    /// use comms::pack::Control;
    /// 
    /// let control = Control::new_iframe(1, false, 0);
    /// ```
    pub fn new_iframe(recv_seq_num: u8, poll: bool, send_seq_num: u8) -> Self {
        assert!(
            recv_seq_num < 8,
            "The receive sequence number must not be more than 7"
        );
        assert!(
            send_seq_num < 8,
            "The send sequence number must not be more than 7"
        );

        let poll_bit: u8 = poll as u8;

        let byte: u8 = (recv_seq_num << 5) | (poll_bit << 4) | (send_seq_num << 1) | 0b0;

        return Control::IFrame {
            recv_seq_num: recv_seq_num,
            poll: poll,
            send_seq_num: send_seq_num,
            byte: byte,
        };
    }

    // TODO: check format of the example (specifically the supervisory function bits (section 4.2.1.2))

    /// A function to create an SFrame AX.25 control field
    /// 
    /// # Fields
    /// - `recv_seq_num`: The receive sequence number is a 3 bit integer. This number is the `send_seq_num` of the next frame to be received
    /// - `poll_final`: A `bool` used to determine if the command should be immediately reponded to
    /// - `supervisory`: The supervisory bit for the SFrame which has a maximum value of 3
    /// 
    /// # Example
    /// Here is an example of a SFrame control field being created for a first packet in a communication which is final.
    /// ```
    /// use comms::pack::Control;
    /// 
    /// let control = Control::new_sframe(1, true, 0);
    /// ```
    pub fn new_sframe(recv_seq_num: u8, poll_final: bool, supervisory: u8) -> Self {
        assert!(
            recv_seq_num < 8,
            "The receive sequence number must not be more than 7"
        );
        assert!(
            supervisory < 4,
            "The send supervisory number must not be more than 3"
        );

        let poll_final_bit: u8 = poll_final as u8;

        let byte: u8 = (recv_seq_num << 5) | (poll_final_bit << 4) | (supervisory << 2) | 0b01;

        return Control::SFrame {
            recv_seq_num: recv_seq_num,
            poll_final: poll_final,
            supervisory: supervisory,
            byte: byte,
        };
    }

    /// A function to create a UFrame AX.25 control field
    /// 
    /// # Fields
    /// - `frame_mod`: A `u8` representing the unnumbered frame modifier bits, this value must be less than 32
    /// - `poll`(IFrame)/`poll_final`(SFrame, UFrame): A `bool` used to determine if the command should be immediately reponded to
    /// 
    /// # Example
    /// Here is an example of a UFrame control field being created for an unnumbered frame that has a frame modifier of 0 and requires an immediate response
    /// ```
    /// use comms::pack::Control;
    /// 
    /// let control = Control::new_uframe(0, true);
    /// ```
    pub fn new_uframe(frame_mod: u8, poll_final: bool) -> Self {
        assert!(frame_mod < 31, "The frame mod must not be more than 31");

        let poll_final_bit: u8 = poll_final as u8;

        let frame_mod_p1: u8 = frame_mod >> 2 << 2; // 3 bits
        let frame_mod_p2: u8 = frame_mod << 6 >> 6; // 2 bits

        let byte: u8 = (frame_mod_p1 << 5) | (poll_final_bit << 4) | (frame_mod_p2 << 2) | 0b11;

        return Control::UFrame {
            frame_mod: frame_mod,
            poll_final: poll_final,
            byte: byte,
        };
    }

    // /// A function to create a modulo 128 IFrame AX.25 control field
    // /// 
    // /// # Fields
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
    // /// # Fields
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
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Pid {
    ISO8208 = 0x01,
    RFC1144C = 0x06,
    RFC1144U = 0x07,
    SegFrag = 0x08,
    TEXNET = 0xC3,
    LinkQuality = 0xC4,
    AppleTalk = 0xCA,
    AppleTalkARP = 0xCB,
    ARPAIP = 0xCC,
    ARPAAR = 0xCD,
    FlexNet = 0xCE,
    NETROM = 0xCF,
    NoL3 = 0xF0,
    EscChar = 0xFF,
}

pub struct Payload<'a> {
    pub length: u64,
    pub data: &'a str,
}

#[derive(Clone, Copy)]
#[repr(u64)]
pub enum CorrelationTag {
    Tag01 = 0xB74DB7DF8A532F3E, // RS(255, 239) 16-byte check value, 239 information bytes
    Tag02 = 0x26FF60A600CC8FDE, // RS(144,128) - shortened RS(255, 239), 128 info bytes
    Tag03 = 0xC7DC0508F3D9B09E, // RS(80,64) - shortened RS(255, 239), 64 info bytes
    Tag04 = 0x8F056EB4369660EE, // RS(48,32) - shortened RS(255, 239), 32 info bytes
    Tag05 = 0x6E260B1AC5835FAE, // RS(255, 223) 32-byte check value, 223 information bytes
    Tag06 = 0xFF94DC634F1CFF4E, // RS(160,128) - shortened RS(255, 223), 128 info bytes
    Tag07 = 0x1EB7B9CDBC09C00E, // RS(96,64) - shortened RS(255, 223), 64 info bytes
    Tag08 = 0xDBF869BD2DBB1776, // RS(64,32) - shortened RS(255, 223), 32 info bytes
    Tag09 = 0x3ADB0C13DEAE2836, // RS(255, 191) 64-byte check value, 191 information bytes
    Tag0A = 0xAB69DB6A543188D6, // RS(192, 128) - shortened RS(255, 191), 128 info bytes
    Tag0B = 0x4A4ABEC4A724B796, // RS(128, 64) - shortened RS(255, 191), 64 info bytes
}

impl CorrelationTag {
    fn to_bytes(&self) -> [u8; 8] {
        return (*self as u64).to_ne_bytes();
    }
}

#[derive(Clone, Copy)]
pub struct Bytes<const N: usize> {
    pub bytes: [u8; N],
    pub pointer: usize,
}

impl<const N: usize> Bytes<N> {
    pub fn new() -> Bytes<N> {
        return Bytes {
            bytes: [0; N],
            pointer: 0,
        }
    }

    pub fn push(&mut self, value: u8) {
        self.bytes[self.pointer] = value;

        self.pointer += 1;
    }

    pub fn extend(&mut self, values: &[u8]) {
        if values.len() + self.pointer >= self.bytes.len() {
            // unreachable!("Values added to bytes must fit in the bytes object.");
        }

        for value in values {
            self.push(*value);
        }
    }
}

pub struct Packet<'a> {
    pub dest_addr: Address<'a>,
    pub source_addr: Address<'a>,
    pub control: Control,
    pub pid: Pid,
    pub payload: Payload<'a>,
    pub bytes: [u8; 191]
}

impl<'a> Packet<'a> {
    pub fn pack_to_ax25(dest_callsign: &'a str, source_callsign: &'a str, recv_seq_num: u8, poll: bool, send_seq_num: u8, pid: Pid, data: &'a str) -> Packet<'a> {
        let dest_addr: Address = Address::new(dest_callsign.into(), 0, true, false);
        let source_addr: Address = Address::new(source_callsign.into(), 0, true, true);
    
        let control: Control = Control::new_iframe(recv_seq_num, poll, send_seq_num);
    
        let payload: Payload = Payload {
            length: data.len() as u64,
            data: data,
        };
        
        let payload_bytes = payload.data.as_bytes();

        let mut bytes: Bytes<191> = Bytes::<191>::new();

        bytes.push(0x7E); // AX.25 opening flag
        bytes.extend(&dest_addr.bytes);
        bytes.extend(&source_addr.bytes);
        
        match control {
            Control::IFrame { byte, .. } => bytes.push(byte),
            Control::SFrame { byte, .. } => bytes.push(byte),
            Control::UFrame { byte, .. } => bytes.push(byte),
        };
        
        bytes.push(pid as u8);
        bytes.extend(&payload_bytes);

        bytes.push(0x7E); // AX.25 closing flag
        
        let packet: Packet<'a> = Packet {
            dest_addr: dest_addr,
            source_addr: source_addr,
            control: control,
            pid: pid,
            payload: payload,
            bytes: bytes.bytes,
        };
        
        return packet;
    }

    pub fn pack_to_fx25(self: Self) -> [u8; 271] {
        let mut bytes: Bytes<271> = Bytes::<271>::new();
        
        bytes.push(0x7E); // FX.25 Opening flags
        bytes.push(0x7E);
        bytes.push(0x7E);
        bytes.push(0x7E);

        bytes.extend(&CorrelationTag::Tag09.to_bytes());

        // let rs: ReedSolomon = ReedSolomon::new();

        let mut ax25_packet_bytes: Bytes<255> = Bytes::<255>::new();
        ax25_packet_bytes.extend(&self.bytes);

        // bytes.extend(&rs.encode(ax25_packet_bytes.bytes));

        bytes.push(0x7E); // FX.25 Closing flags
        bytes.push(0x7E);
        bytes.push(0x7E);
        bytes.push(0xFE);

        return bytes.bytes;
    }

    pub fn decode_fx25(bytes: [u8; 271]) -> [u8; 191] {
        // let rs: ReedSolomon = ReedSolomon::new();

        let mut correlation_tag: Bytes<8> = Bytes::<8>::new();
        correlation_tag.extend(&bytes[4..12]);

        if correlation_tag.bytes == CorrelationTag::Tag09.to_bytes() {
            // return rs.decode(bytes);    
        }

        return [0u8; 191];
    }
}
