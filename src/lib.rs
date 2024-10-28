#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#![cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

pub mod pack;

#[cfg(feature = "ground-station")]
mod ground_station {
    use pyo3::prelude::*;

    use pack::Packet;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
        Ok((a + b).to_string())
    }
    
    /// A Python module implemented in Rust.
    #[pymodule]
    pub fn comms(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
        Ok(())
    }
    
    #[cfg(test)]
    mod test;
}

#[cfg(feature = "cubesat")]
mod cubesat {
    use crate::pack::{Packet, Pid};

    pub fn load_to_transmit(dest_callsign: &str, source_callsign: &str, data: &str) -> [u8; 249] {
        let ax25_packet: Packet = Packet::pack_to_ax25(dest_callsign, source_callsign, 1, true, 2, Pid::NoL3, data);
        let fx25_bytes: [u8; 249] = ax25_packet.pack_to_fx25();

        return fx25_bytes;
    }
}

#[cfg(feature = "cubesat")]
#[no_mangle]
pub extern "C" fn main() -> ! {
    let dest_callsign = "DESTCALL";
    let source_callsign = "SRCCALL";
    let data = "Hello, CubeSat!";
    
    let _fx25_bytes = cubesat::load_to_transmit(dest_callsign, source_callsign, data);
    
    loop {
    }
}
