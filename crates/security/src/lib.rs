//! Citadel Security Crate
//!
//! This crate handles security policies, context management, and enforcement mechanisms
//! crucial for maintaining user privacy and safety.

pub mod context;
pub mod error;
// pub mod policy; // Potential future module

pub use context::{SecurityContext, SecurityContextBuilder, UrlScheme};
pub use error::SecurityError; 