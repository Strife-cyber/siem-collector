//! SIEM Collector – core library.
//!
//! This crate collects Windows Event Log data (and eventually Linux, firewall,
//! web server, and network device logs) and persists them to a local
//! write-ahead log (WAL) file for reliable shipping to a central SIEM.

pub mod config;
pub mod coordinator;
pub mod flow;
pub mod logs;
pub mod normalize;
pub mod shipper;
pub mod storage;
pub mod types;
pub mod utils;
