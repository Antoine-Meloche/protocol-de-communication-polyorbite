use crate::utils::{ceil_div, str_to_6_u8_array};

pub struct Address {
    callsign: [u8; 6],
    ssid: u8, // MAX 4 bits
    bytes: [u8; 7],
}

impl Address {
    fn new(callsign: &str, ssid: u8, command: bool, last_addr: bool) -> Self {
        if callsign.chars().count() > 6 {
            panic!("The callsign cannot be longer than 6 characters");
        }

        if ssid > 15 {
            panic!(
                "The destination SSID is larger than the allowed amount (15): {} > 15",
                ssid
            );
        }

        let callsign_bytes: [u8; 6] = str_to_6_u8_array(callsign);

        let ssid_byte: u8 = (ssid << 1) | 0b01100000 | (last_addr as u8) | ((((!command & !last_addr) | ((command & last_addr))) as u8) << 7);

        let bytes: [u8; 7] = {
            let mut temp: [u8; 7] = [0u8; 7];
            temp[..6].copy_from_slice(&callsign_bytes);
            temp[6] = ssid_byte;
            temp
        };

        return Address {
            callsign: callsign_bytes,
            ssid: ssid,
            bytes: bytes,
        };
    }
}

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

    IFrame128 {
        recv_seq_num: u8, // 7 bits
        poll: bool,       // 1 bit
        send_seq_num: u8, // 7 bits
        bytes: u16,       // fully constructed i frame modulo 128 control bytes
    },
    SFrame128 {
        recv_seq_num: u8, // 7 bits
        poll_final: bool, // 1 bit
        supervisory: u8,  // 2 bits
        bytes: u16,       // fully constructed s frame modulo 128 control bytes
    },
}

impl Control {
    fn new_iframe(recv_seq_num: u8, poll: bool, send_seq_num: u8) -> Self {
        assert!(
            recv_seq_num < 8,
            "The receive sequence number must not be more than 7"
        );
        assert!(
            send_seq_num < 8,
            "The send sequence number must not be more than 7"
        );

        let poll_bit = poll as u8;

        let byte = (recv_seq_num << 5) | (poll_bit << 4) | (send_seq_num << 1) | 0b0;

        return Control::IFrame {
            recv_seq_num: recv_seq_num,
            poll: poll,
            send_seq_num: send_seq_num,
            byte: byte,
        };
    }

    fn new_sframe(recv_seq_num: u8, poll_final: bool, supervisory: u8) -> Self {
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

    fn new_uframe(frame_mod: u8, poll_final: bool) -> Self {
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

    fn new_iframe128(recv_seq_num: u8, poll: bool, send_seq_num: u8) -> Self {
        assert!(
            recv_seq_num < 128,
            "The receive sequence number must not be more than 127"
        );
        assert!(
            send_seq_num < 128,
            "The send sequence number must not be more than 127"
        );

        let poll_bit: u16 = poll as u16;

        let bytes: u16 =
            ((recv_seq_num as u16) << 9) | (poll_bit << 8) | ((send_seq_num as u16) << 1) | 0b0;

        return Control::IFrame128 {
            recv_seq_num: recv_seq_num,
            poll: poll,
            send_seq_num: send_seq_num,
            bytes: bytes,
        };
    }

    fn new_sframe128(recv_seq_num: u8, poll_final: bool, supervisory: u8) -> Self {
        assert!(
            recv_seq_num < 128,
            "The receive sequence number must not be more than 127"
        );
        assert!(
            supervisory < 4,
            "The supervisory number must not be more than 3"
        );

        let poll_final_bit: u16 = poll_final as u16;

        let bytes: u16 = ((recv_seq_num as u16) << 9)
            | (poll_final_bit << 8)
            | 0b0000
            | ((supervisory as u16) << 2)
            | 0b01;

        return Control::SFrame128 {
            recv_seq_num: recv_seq_num,
            poll_final: poll_final,
            supervisory: supervisory,
            bytes: bytes,
        };
    }
}

#[repr(u8)]
enum Pid {
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

pub struct Payload {
    length: u64,
    data: String,
}

impl Payload {
    fn new<S: Into<String>>(str: S) -> Self {
        let string = str.into();

        return Payload {
            length: string.len() as u64,
            data: string,
        };
    }
}

pub struct Packet {
    dest_addr: Address,
    source_addr: Address,
    control: Control,
    pid: Pid,
    payload: Payload,
}

pub fn pack_to_ax25(data: String) -> Packet {
    let dest_addr: Address = Address::new("NJ7P", 0, true, false);
    let source_addr: Address = Address::new("N7LEM", 0, true, true);

    let control: Control = Control::new_iframe(1, true, 2);

    let pid: Pid = Pid::NoL3;

    let payload: Payload = Payload::new(data);

    let packet: Packet = Packet {
        dest_addr: dest_addr,
        source_addr: source_addr,
        control: control,
        pid: pid,
        payload: payload,
    };

    let payload_bytes_length: u128 = ceil_div(packet.payload.length as u128, 8);

    // TODO: create [u8; payload_bytes_length] array with the bytes of the payload string.

    let bytes: [u8; 16+payload_bytes_length] = {
        let mut temp: [u8; 7] = [0u8; 16+payload_bytes_length];
        temp[0..7] = packet.dest_addr.bytes;
        temp[7..14] = packet.source_addr.bytes;
        temp[14] = packet.control.byte; // if the control frame is not modulo 128
        temp[15] = packet.pid.byte;
        temp[16..]copy_from_slice(&payload_bytes);

        temp
    };

    return packet;
}
