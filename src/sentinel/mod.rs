//! Sentinel — Real-Time Hack Detection System
//!
//! Pre-filters every transaction receipt in a block using lightweight heuristics,
//! flagging suspicious transactions for deep analysis via the Autopsy Lab pipeline.

#[cfg(feature = "ai_agent")]
pub mod ai;
pub mod alert;
pub mod analyzer;
pub mod auto_pause;
pub mod config;
pub mod history;
pub mod http_metrics;
pub mod mempool_filter;
pub mod metrics;
pub mod ml_model;
pub mod pipeline;
pub mod pre_filter;
pub mod replay;
#[cfg(feature = "ai_agent")]
pub(crate) mod rpc_ai;
pub mod rpc_poller;
pub mod rpc_replay;
pub mod rpc_service;
pub mod rpc_types;
pub mod service;
pub mod types;
pub mod webhook;
pub mod whitelist;
pub mod whitelist_config;
pub mod ws_broadcaster;

#[cfg(test)]
mod tests;
