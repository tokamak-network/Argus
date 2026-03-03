//! Tokamak Time-Travel Debugger
//!
//! Replays Ethereum transactions at opcode granularity, recording each step's
//! VM state. Supports forward/backward/random-access navigation through the
//! execution trace.

pub mod engine;
pub mod error;
pub mod recorder;
pub mod types;

#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "autopsy")]
pub mod autopsy;

#[cfg(feature = "sentinel")]
pub mod sentinel;

#[cfg(test)]
mod tests;
