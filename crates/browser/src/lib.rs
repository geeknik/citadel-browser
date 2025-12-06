//! Citadel Browser - Privacy-First Web Browser
//! 
//! A secure-by-design, privacy-first browser built from scratch in Rust.
//! Citadel Browser puts user agency first with zero-knowledge architecture,
//! anti-fingerprinting, and a security-focused rendering engine.
//! 
//! Homepage: https://citadelbrowser.com
//! Author: Deep Fork Cyber - https://deepforkcyber.com

pub mod app;
pub mod ui;
pub mod engine;
pub mod resource_loader;
pub mod tabs;
pub mod renderer;
pub mod zkvm_receiver;
pub mod performance;

// Re-export the main application
pub use app::CitadelBrowser;

// Re-export common types
pub use engine::{CitadelEngine, LoadingError, WebPage};
pub use resource_loader::ResourceLoader;
pub use ui::{CitadelUI, UIMessage};
pub use renderer::CitadelRenderer;
pub use performance::{PerformanceMonitor, MemoryConfig, CleanupPriority, MemoryPressure};