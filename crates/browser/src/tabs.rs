//! This module re-exports tab functionality from the citadel-tabs crate
//! to maintain compatibility with the browser module structure.

// Re-export simple tab types for browser compatibility
pub use citadel_tabs::{SimpleTab as Tab, SimpleTabManager as TabManager};