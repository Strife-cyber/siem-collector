//! Web server log collectors.
//!
//! Supports Nginx, Apache, and Traefik (via Docker logs or file).
//! All collectors are file-tail or process-stream based and implement
//! the standard [`Collector`] trait.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────┐
//! │            WebServerCoordinator            │
//! ├──────────┬──────────┬──────────────────────┤
//! │  Nginx   │  Apache  │  Traefik             │
//! │ access   │ access   │ docker logs -f       │
//! │ error    │ error    │ or file tail         │
//! └──────────┴──────────┴──────────────────────┘
//! ```

pub mod apache;
pub mod coordinator;
pub mod nginx;
pub mod traefik;
