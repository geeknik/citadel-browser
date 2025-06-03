use std::sync::Arc;
use tokio::runtime::Runtime;
use iced::{Application, Command, Element, Subscription, Theme};
use url::Url;

use crate::ui::{CitadelUI, UIMessage};
use crate::engine::BrowserEngine;
use crate::tabs::TabManager;
use citadel_networking::{NetworkConfig, PrivacyLevel};
use citadel_security::SecurityContext;

/// Main Citadel Browser application
pub struct CitadelBrowser {
    /// Async runtime for network operations
    runtime: Arc<Runtime>,
    /// Browser engine for page loading and rendering
    engine: Option<BrowserEngine>,
    /// UI state and components
    ui: CitadelUI,
    /// Tab management
    tab_manager: Arc<TabManager>,
    /// Network configuration
    network_config: NetworkConfig,
    /// Security context
    security_context: Arc<SecurityContext>,
}

/// Messages that can be sent to the browser application
#[derive(Debug, Clone)]
pub enum Message {
    /// UI-related messages
    UI(UIMessage),
    /// Navigate to a URL
    Navigate(String),
    /// Page loading completed
    PageLoaded(Result<String, String>),
    /// Create a new tab
    NewTab,
    /// Close a tab
    CloseTab(uuid::Uuid),
    /// Switch to a tab
    SwitchTab(uuid::Uuid),
    /// Update privacy settings
    UpdatePrivacy(PrivacyLevel),
    /// Engine initialization completed
    EngineInitialized(BrowserEngine),
    /// Initialization error
    InitializationError(String),
}

impl Application for CitadelBrowser {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = Arc<Runtime>;

    fn new(runtime: Arc<Runtime>) -> (Self, Command<Message>) {
        log::info!("Initializing Citadel Browser application");
        
        // Initialize security context with high privacy by default
        let security_context = Arc::new(SecurityContext::new_with_high_security());
        
        // Initialize network configuration with maximum privacy
        let network_config = NetworkConfig {
            privacy_level: PrivacyLevel::High,
            dns_mode: citadel_networking::DnsMode::LocalCache,
            enforce_https: true,
            randomize_user_agent: true,
            strip_tracking_params: true,
        };
        
        // Initialize tab manager
        let tab_manager = Arc::new(TabManager::new());
        
        // Initialize UI
        let ui = CitadelUI::new();
        
        let browser = Self {
            runtime: runtime.clone(),
            engine: None, // Will be initialized lazily
            ui,
            tab_manager,
            network_config: network_config.clone(),
            security_context: security_context.clone(),
        };
        
        // Initialize browser engine asynchronously
        let init_command = Command::perform(
            BrowserEngine::new(runtime, network_config, security_context),
            |result| match result {
                Ok(engine) => Message::EngineInitialized(engine),
                Err(e) => Message::InitializationError(format!("Failed to initialize engine: {}", e)),
            }
        );
        
        (browser, init_command)
    }

    fn title(&self) -> String {
        let version = env!("CARGO_PKG_VERSION");
        let base_title = format!("Citadel Browser v{} (Alpha)", version);
        
        if let Some(active_tab) = self.tab_manager.active_tab() {
            let title = active_tab.title();
            if title.is_empty() {
                base_title
            } else {
                format!("{} - {}", title, base_title)
            }
        } else {
            base_title
        }
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::UI(ui_message) => {
                self.ui.update(ui_message)
            }
            
            Message::Navigate(url_str) => {
                log::info!("Navigating to: {}", url_str);
                
                // Check if engine is initialized
                if self.engine.is_none() {
                    log::warn!("Engine not yet initialized, cannot navigate");
                    return Command::none();
                }
                
                // Validate and parse URL
                match Url::parse(&url_str) {
                    Ok(url) => {
                        // Create new tab or update current tab
                        let _tab_id = if let Some(active_tab) = self.tab_manager.active_tab() {
                            active_tab.set_url(url_str.clone());
                            active_tab.set_loading(true);
                            active_tab.id()
                        } else {
                            self.tab_manager.create_tab(url_str.clone())
                        };
                        
                        // Load the page
                        let engine = self.engine.clone().unwrap();
                        Command::perform(
                            async move {
                                engine.load_page(url).await
                            },
                            Message::PageLoaded,
                        )
                    }
                    Err(e) => {
                        log::error!("Invalid URL: {} - {}", url_str, e);
                        Command::none()
                    }
                }
            }
            
            Message::PageLoaded(result) => {
                // Update the active tab with the loaded content
                if let Some(active_tab) = self.tab_manager.active_tab() {
                    active_tab.set_loading(false);
                    
                    match result {
                        Ok(content) => {
                            log::info!("Page loaded successfully, {} bytes", content.len());
                            // TODO: Parse and render the content
                            // For now, just update the tab title
                            if let Some(title) = extract_title(&content) {
                                active_tab.set_title(title);
                            }
                        }
                        Err(error) => {
                            log::error!("Failed to load page: {}", error);
                            active_tab.set_title("Failed to load".to_string());
                        }
                    }
                }
                Command::none()
            }
            
            Message::NewTab => {
                log::info!("Creating new tab");
                let homepage = "https://citadelbrowser.com".to_string();
                let _tab_id = self.tab_manager.create_tab(homepage);
                Command::none()
            }
            
            Message::CloseTab(tab_id) => {
                log::info!("Closing tab: {}", tab_id);
                self.tab_manager.close_tab(tab_id);
                Command::none()
            }
            
            Message::SwitchTab(tab_id) => {
                log::info!("Switching to tab: {}", tab_id);
                self.tab_manager.set_active_tab(tab_id);
                Command::none()
            }
            
            Message::UpdatePrivacy(level) => {
                log::info!("Updating privacy level to: {:?}", level);
                self.network_config.privacy_level = level;
                
                // Update engine config if engine is initialized
                if let Some(engine) = self.engine.take() {
                    let config = self.network_config.clone();
                    return Command::perform(
                        async move {
                            engine.update_network_config(config).await
                        },
                        |result| match result {
                            Ok(updated_engine) => Message::EngineInitialized(updated_engine),
                            Err(e) => Message::InitializationError(format!("Failed to update config: {}", e)),
                        }
                    );
                }
                Command::none()
            }
            
            Message::EngineInitialized(engine) => {
                log::info!("Browser engine initialized successfully");
                self.engine = Some(engine);
                Command::none()
            }
            
            Message::InitializationError(error) => {
                log::error!("Engine initialization failed: {}", error);
                // TODO: Show error to user in UI
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        self.ui.view(&self.tab_manager, &self.network_config)
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::none()
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

/// Extract title from HTML content (basic implementation)
fn extract_title(html: &str) -> Option<String> {
    // Simple regex-based title extraction
    // TODO: Use proper HTML parsing from citadel-parser
    if let Some(start) = html.find("<title>") {
        if let Some(end) = html[start + 7..].find("</title>") {
            let title = &html[start + 7..start + 7 + end];
            return Some(title.trim().to_string());
        }
    }
    None
}