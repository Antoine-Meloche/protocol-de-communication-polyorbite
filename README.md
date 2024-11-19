# Comms Library

A Rust library for handling AX.25 and FX.25 packet radio communications with Reed-Solomon error correction. This library provides both ground station and CubeSat implementations.

## Features

- AX.25 packet encoding and decoding
- FX.25 frame support with Reed-Solomon error correction
- Galois Field (GF(2^8)) arithmetic implementation
- Ground station and CubeSat configurations
- Python bindings via PyO3

## Installation

Add this to your `Cargo.toml`:
```toml
[dependencies]
comms = "0.1.0"
```

## Usage

### Ground Station Mode

```rust
use comms::pack::{Packet, Pid};
// Create and encode an AX.25 packet
let packet = Packet::pack_to_ax25(
"DESTCALL", // Destination callsign
"SOURCECAL", // Source callsign
1, // Receive sequence number
true, // Poll bit
2, // Send sequence number
Pid::NoL3, // Protocol ID
"Hello World!" // Data payload
);
// Convert to FX.25 format with error correction
let fx25_bytes = packet.pack_to_fx25();
// Decode received FX.25 data
let decoded_bytes = Packet::decode_fx25(fx25_bytes);
```

### CubeSat Mode

```rust
use comms::cubesat::load_to_transmit;
// Prepare data for transmission
let fx25_bytes = load_to_transmit(
"DESTCALL", // Destination callsign
"SOURCECAL", // Source callsign
"Hello World!" // Data payload
);
```

## Feature Flags

- `ground-station` (default): Enables ground station functionality
- `cubesat`: Enables CubeSat-specific functionality
- `fuzz`: Enables fuzzing tests for Galois Field operations

## Technical Details

### AX.25 Implementation
- Supports both modulo-8 and modulo-128 sequence numbers
- Implements I-frames, S-frames, and U-frames
- Full address field handling with callsign encoding

### FX.25 Features
- Correlation tag support for frame synchronization
- Reed-Solomon error correction using GF(2^8)
- Multiple RS code configurations available

### Error Correction
- Uses Reed-Solomon codes over GF(2^8)
- Supports error detection and correction
- Implements efficient Galois Field arithmetic

## Building

### Build with default features (ground-station)
```cargo build --release```

### Build with CubeSat features
```cargo build --release --features cubesat