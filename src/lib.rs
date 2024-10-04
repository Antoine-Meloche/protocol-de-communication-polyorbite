#[cfg(ground_station)]
use pyo3::prelude::*;
mod pack;

mod utils;

/// Formats the sum of two numbers as string.
#[cfg(ground_station)]
#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

/// A Python module implemented in Rust.
#[cfg(ground_station)]
#[pymodule]
fn comms(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    Ok(())
}
