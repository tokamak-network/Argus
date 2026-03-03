//! Smart Contract Autopsy Lab
//!
//! Post-hack analysis toolkit that replays transactions against remote archive
//! nodes, detects attack patterns, traces fund flows, and generates reports.

pub mod abi_decoder;
pub mod classifier;
pub mod enrichment;
pub mod fund_flow;
pub mod metrics;
pub mod remote_db;
pub mod report;
pub mod rpc_client;
pub mod types;
