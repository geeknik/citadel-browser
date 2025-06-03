//! This module re-exports tab functionality from the citadel-tabs crate
//! using the full ZKVM-based tab manager for proper isolation.

// Re-export ZKVM tab types for proper security isolation
pub use citadel_tabs::{Tab, SendSafeTabManager as TabManager, TabType, TabState};