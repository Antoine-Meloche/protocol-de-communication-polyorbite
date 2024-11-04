#![cfg_attr(not(feature = "std"), no_std)]

pub mod pack;
pub mod reed_solomon;
pub mod gf;

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
pub mod cubesat{
    use crate::pack::{Packet, Pid};

    pub fn load_to_transmit(dest_callsign: &str, source_callsign: &str, data: &str) -> [u8; 271] {
        let ax25_packet: Packet = Packet::pack_to_ax25(dest_callsign, source_callsign, 1, true, 2, Pid::NoL3, data);
        let fx25_bytes: [u8; 271] = ax25_packet.pack_to_fx25();

        return fx25_bytes;
    }
}