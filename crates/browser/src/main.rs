use std::sync::Arc;
use tokio::runtime::Runtime;
use iced::{Application, Settings, window};

mod app;
mod ui;
mod engine;
mod resource_loader;
mod renderer;

use app::CitadelBrowser;

fn main() -> iced::Result {
    // Initialize logging
    env_logger::init();
    
    log::info!("Starting Citadel Browser v{} - Privacy-First Web Browser", env!("CARGO_PKG_VERSION"));
    log::warn!("⚠️  ALPHA SOFTWARE - USE AT YOUR OWN RISK ⚠️");
    log::warn!("This is experimental software not intended for production use");
    log::info!("Homepage: https://citadelbrowser.com");
    log::info!("Author: Deep Fork Cyber - https://deepforkcyber.com");
    
    // Create the Tokio runtime for async operations
    let rt = Arc::new(Runtime::new().expect("Failed to create Tokio runtime"));
    
    // Configure the application window
    let settings = Settings::with_flags(rt);
    
    CitadelBrowser::run(settings)
}