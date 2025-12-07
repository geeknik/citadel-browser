//! Citadel Browser - Privacy-First Web Browser
//!
//! A secure-by-design, privacy-first browser built from scratch in Rust.
//! Citadel Browser puts user agency first with zero-knowledge architecture,
//! anti-fingerprinting, and a security-focused rendering engine.
//!
//! Homepage: https://citadelbrowser.com
//! Author: Deep Fork Cyber - https://deepforkcyber.com

use log::{info, debug, warn, error};

pub mod app;
pub mod ui;
pub mod ui_modern;
pub mod theme;
pub mod settings;
pub mod settings_panel;
pub mod engine;
pub mod resource_loader;
pub mod tabs;
pub mod history;
pub mod bookmarks;
pub mod downloads;
pub mod renderer;
pub mod renderer_backup;
pub mod zkvm_receiver;
pub mod performance;

// Performance optimization modules
pub mod memory_manager;
pub mod render_optimizer;
pub mod performance_integrator;
pub mod performance_benchmark;
pub mod performance_dashboard;

// Re-export the main application
pub use app::CitadelBrowser;

// Re-export common types
pub use engine::{CitadelEngine, LoadingError, WebPage};
pub use resource_loader::ResourceLoader;
pub use ui::{CitadelUI, UIMessage};
pub use ui_modern::{CitadelModernUI, ModernUIMessage};
pub use theme::{CitadelTheme, ThemeManager};
pub use settings_panel::{SettingsPanel, SettingsMessage};
pub use renderer::CitadelRenderer;
pub use performance::{PerformanceMonitor, MemoryConfig, CleanupPriority, MemoryPressure};

// Re-export performance optimization types
pub use memory_manager::{MemoryManager, TabMemoryTracker, CleanupStrategy as MemoryCleanupStrategy};
pub use render_optimizer::{RenderOptimizer, Viewport, DirtyRegion, ScrollAnimation, FrameStats};
pub use performance_integrator::{PerformanceIntegrator, PerformanceReport, PerformanceRecommendation, PerformanceTargets};
pub use performance_benchmark::{PerformanceBenchmark, BenchmarkReport, BenchmarkResult};
pub use performance_dashboard::{PerformanceDashboard, DashboardMessage, RealTimeMetrics};