//! Firewall / network appliance log collectors.
//!
//! Unlike file-based collectors, firewalls **push** logs via syslog (UDP 514).
//! This module provides a syslog receiver that wraps each incoming datagram
//! into a `CollectorLogRecord`.
//!
//! # Architecture
//!
//! ```text
//! Firewall ──UDP 514──→ SyslogListener ──→ CollectorLogRecord ──→ channel
//! ```
//!
//! All devices that support RFC 3164 / RFC 5424 syslog are supported:
//! pfSense, Cisco ASA, Fortinet, Palo Alto, iptables, UFW, and more.

pub mod coordinator;
pub mod syslog;
