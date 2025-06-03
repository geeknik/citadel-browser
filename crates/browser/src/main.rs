use std::sync::Arc;
use tokio::runtime::Runtime;
use iced::{Application, Settings, window};

mod app;
mod ui;
mod engine;
mod resource_loader;

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
    let settings = Settings {
        window: window::Settings {
            size: (1200, 800),
            min_size: Some((800, 600)),
            position: window::Position::Centered,
            resizable: true,
            decorations: true,
            transparent: false,
            always_on_top: false,
            icon: None,
        },
        flags: rt,
        default_font: None,
        default_text_size: 14,
        antialiasing: true,
        exit_on_close_request: true,
        try_opengles_first: false,
    };
    
    CitadelBrowser::run(settings)
}