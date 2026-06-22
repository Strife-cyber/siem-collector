//! Linux log collectors.
//!
//! Each module implements the [`Collector`] trait for a specific Linux log source.
//! The [`coordinator`] module spawns all of them.
//!
//! All paths are Linux-specific and this module only compiles on `target_os = "linux"`.

pub(crate) mod tailer;

pub mod auditd;
pub mod auth;
pub mod coordinator;
pub mod journal;
pub mod kern;
pub mod network;
pub mod process;
pub mod syslog;
