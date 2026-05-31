//! Citadel Browser - Privacy-First Web Browser
//!
//! A secure-by-design, privacy-first browser built from scratch in Rust.
//! Citadel Browser puts user agency first with zero-knowledge architecture,
//! anti-fingerprinting, and a security-focused rendering engine.
//!
//! Homepage: https://citadelbrowser.com
//! Author: Deep Fork Cyber - https://deepforkcyber.com

pub mod app;
pub mod engine;
pub mod memory_protection;
pub mod performance;
pub mod renderer;
pub mod resource_loader;
pub mod tabs;
pub mod ui;

// Re-export the main application
pub use app::CitadelBrowser;

// Re-export common types
pub use engine::BrowserEngine;
pub use memory_protection::{BrowserMemoryManager, BrowserMemoryStatistics};
pub use performance::{CleanupPriority, MemoryConfig, MemoryPressure, PerformanceMonitor};
pub use renderer::CitadelRenderer;
pub use resource_loader::ResourceLoader;
pub use ui::{CitadelUI, UIMessage};
