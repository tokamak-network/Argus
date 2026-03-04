mod helpers;

mod basic_replay;
mod error_handling;
mod gas_tracking;
mod navigation;
mod nested_calls;
mod recorder_edge_cases;
mod serde_tests;

#[cfg(feature = "cli")]
mod cli_tests;

#[cfg(feature = "autopsy")]
mod autopsy_tests;

#[cfg(feature = "autopsy")]
mod stress_tests;

#[cfg(feature = "autopsy")]
mod mainnet_validation;

#[cfg(feature = "autopsy")]
mod exploit_fixtures;

#[cfg(feature = "autopsy")]
mod exploit_smoke_tests;

#[cfg(all(feature = "autopsy", feature = "cli"))]
mod autopsy_cli;
