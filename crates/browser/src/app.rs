//! Enhanced Citadel Browser application with comprehensive error handling and user feedback
//! 
//! This module implements the main browser application with security-first design,
//! ZKVM tab isolation, and privacy-preserving features.

use std::sync::Arc;
use std::collections::HashMap;
use tokio::runtime::Runtime;
use iced::{Application, Command, Element, Subscription, Theme};
use url::Url;

use crate::ui::{CitadelUI, UIMessage};
use crate::engine::BrowserEngine;
use crate::renderer::CitadelRenderer;
use citadel_tabs::{SendSafeTabManager as TabManager, TabType, PageContent};
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
    /// HTML/CSS renderer
    renderer: CitadelRenderer,
    /// Tab management with ZKVM isolation
    tab_manager: Arc<TabManager>,
    /// Network configuration for privacy
    network_config: NetworkConfig,
    /// Security context for all operations
    security_context: Arc<SecurityContext>,
    /// Error states for better user feedback
    error_states: HashMap<uuid::Uuid, String>,
    /// Loading states for tab operations
    loading_states: HashMap<uuid::Uuid, LoadingState>,
}

/// Detailed loading states for better user feedback
#[derive(Debug, Clone, PartialEq)]
pub enum LoadingState {
    /// Tab is idle
    Idle,
    /// Resolving DNS for the domain
    ResolvingDns { domain: String },
    /// Establishing connection
    Connecting { url: String },
    /// Loading page content
    LoadingContent { progress: f32 },
    /// Parsing HTML content
    ParsingContent,
    /// Applying security policies
    ApplyingSecurity,
    /// Finalizing page render
    Finalizing,
}

/// Messages that can be sent to the browser application
#[derive(Debug, Clone)]
pub enum Message {
    /// UI-related messages
    UI(UIMessage),
    /// Navigate to a URL with enhanced error handling
    Navigate(String),
    /// Page loading completed with detailed result
    PageLoaded(uuid::Uuid, Result<ParsedPageData, LoadingError>),
    /// Create a new tab with specific configuration
    NewTab { tab_type: TabType, initial_url: Option<String> },
    /// Close a tab with cleanup
    CloseTab(uuid::Uuid),
    /// Switch to a tab
    SwitchTab(uuid::Uuid),
    /// Update privacy settings
    UpdatePrivacy(PrivacyLevel),
    /// Engine initialization completed
    EngineInitialized(BrowserEngine),
    /// Initialization error with detailed context
    InitializationError(String),
    /// Loading state update for user feedback
    LoadingStateUpdate(uuid::Uuid, LoadingState),
    /// Clear error state for a tab
    ClearError(uuid::Uuid),
    /// Refresh current tab
    RefreshTab,
    /// Stop loading current tab
    StopLoading(uuid::Uuid),
}

/// Detailed loading error information
#[derive(Debug, Clone)]
pub struct LoadingError {
    pub error_type: ErrorType,
    pub message: String,
    pub url: String,
    pub timestamp: std::time::SystemTime,
    pub retry_possible: bool,
}

/// Types of loading errors for better categorization
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorType {
    /// Network-related errors (DNS, connection, timeout)
    Network,
    /// Security policy violations
    Security,
    /// Invalid or malformed content
    Content,
    /// Resource exhaustion or limits exceeded
    Resource,
    /// Internal browser errors
    Internal,
}

/// Structured page data from the engine
#[derive(Debug, Clone)]
pub struct ParsedPageData {
    pub title: String,
    pub content: String,
    pub element_count: usize,
    pub size_bytes: usize,
    pub url: String,
    pub load_time_ms: u64,
    pub security_warnings: Vec<String>,
    pub dom: Option<std::sync::Arc<citadel_parser::Dom>>,
    pub stylesheet: Option<std::sync::Arc<citadel_parser::CitadelStylesheet>>,
}

impl Application for CitadelBrowser {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = Arc<Runtime>;

    fn new(runtime: Arc<Runtime>) -> (Self, Command<Message>) {
        log::info!("🚀 Initializing Citadel Browser application with enhanced security");
        
        // Initialize security context with maximum privacy by default
        let security_context = Arc::new(SecurityContext::new());
        
        // Initialize network configuration with privacy-first settings
        let network_config = NetworkConfig {
            privacy_level: PrivacyLevel::High,
            dns_mode: citadel_networking::DnsMode::LocalCache,
            enforce_https: true,
            randomize_user_agent: true,
            strip_tracking_params: true,
        };
        
        // Initialize tab manager with ZKVM isolation
        let tab_manager = Arc::new(TabManager::new());
        
        // Initialize UI with enhanced features
        let ui = CitadelUI::new();
        
        // Initialize HTML/CSS renderer
        let renderer = CitadelRenderer::new();
        
        let browser = Self {
            runtime: runtime.clone(),
            engine: None,
            ui,
            renderer,
            tab_manager,
            network_config: network_config.clone(),
            security_context: security_context.clone(),
            error_states: HashMap::new(),
            loading_states: HashMap::new(),
        };
        
        // Initialize browser engine asynchronously with detailed error handling
        let init_command = Command::perform(
            BrowserEngine::new(runtime, network_config, security_context),
            |result| match result {
                Ok(engine) => {
                    log::info!("✅ Browser engine initialized successfully");
                    Message::EngineInitialized(engine)
                }
                Err(e) => {
                    log::error!("❌ Engine initialization failed: {}", e);
                    Message::InitializationError(format!("Failed to initialize engine: {}", e))
                }
            }
        );
        
        (browser, init_command)
    }

    fn title(&self) -> String {
        let version = env!("CARGO_PKG_VERSION");
        let base_title = format!("Citadel Browser v{} (Alpha) - Privacy First", version);
        
        // Get active tab from tab states
        let tab_states = self.tab_manager.get_tab_states();
        if let Some(active_tab) = tab_states.iter().find(|tab| tab.is_active) {
            // Show loading state in title if applicable
            if let Some(loading_state) = self.loading_states.get(&active_tab.id) {
                match loading_state {
                    LoadingState::Idle => {},
                    LoadingState::ResolvingDns { domain } => {
                        return format!("🔍 Resolving {} - {}", domain, base_title);
                    }
                    LoadingState::Connecting { .. } => {
                        return format!("🔗 Connecting... - {}", base_title);
                    }
                    LoadingState::LoadingContent { progress } => {
                        return format!("📥 Loading {:.0}% - {}", progress * 100.0, base_title);
                    }
                    LoadingState::ParsingContent => {
                        return format!("🔧 Processing... - {}", base_title);
                    }
                    LoadingState::ApplyingSecurity => {
                        return format!("🛡️ Securing... - {}", base_title);
                    }
                    LoadingState::Finalizing => {
                        return format!("✨ Finalizing... - {}", base_title);
                    }
                }
            }
            
            // Show error state in title if applicable
            if self.error_states.contains_key(&active_tab.id) {
                return format!("❌ Error - {}", base_title);
            }
            
            // Show normal tab title
            if active_tab.title.is_empty() {
                base_title
            } else {
                format!("{} - {}", active_tab.title, base_title)
            }
        } else {
            base_title
        }
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::UI(ui_message) => {
                match &ui_message {
                    UIMessage::AddressBarSubmitted => {
                        let url = self.ui.address_bar_value().to_string();
                        if !url.is_empty() {
                            return self.update(Message::Navigate(url));
                        }
                    }
                    _ => {}
                }
                self.ui.update(ui_message)
            }
            
            Message::Navigate(url_str) => {
                log::info!("🧭 Navigating to: {}", url_str);
                
                // Check if engine is initialized
                if self.engine.is_none() {
                    log::warn!("⚠️ Engine not yet initialized, cannot navigate");
                    return Command::none();
                }
                
                // Enhanced URL validation and normalization
                let normalized_url = self.normalize_url(&url_str);
                match Url::parse(&normalized_url) {
                    Ok(url) => {
                        // Get or create active tab
                        let tab_states = self.tab_manager.get_tab_states();
                        if tab_states.is_empty() {
                            // Create a new tab first
                            return self.update(Message::NewTab { 
                                tab_type: TabType::Ephemeral, 
                                initial_url: Some(url_str) 
                            });
                        }
                        
                        if let Some(active_tab) = tab_states.iter().find(|tab| tab.is_active) {
                            let tab_id = active_tab.id;
                            
                            // Clear any existing error state
                            self.error_states.remove(&tab_id);
                            
                            // Set initial loading state
                            self.loading_states.insert(tab_id, LoadingState::ResolvingDns { 
                                domain: url.host_str().unwrap_or("unknown").to_string() 
                            });
                            
                            // Update tab content to loading state
                            let tab_manager = self.tab_manager.clone();
                            let loading_content = PageContent::Loading { url: normalized_url.clone() };
                            
                            // Start the page loading process
                            let engine = self.engine.clone().unwrap();
                            return Command::batch([
                                // Set loading state in tab
                                Command::perform(
                                    async move {
                                        let _ = tab_manager.update_page_content(tab_id, loading_content).await;
                                    },
                                    {
                                        let tab_id_copy = tab_id;
                                        let url_copy = normalized_url.clone();
                                        move |_| Message::LoadingStateUpdate(tab_id_copy, LoadingState::Connecting { 
                                            url: url_copy 
                                        })
                                    }
                                ),
                                // Start loading the page
                                Command::perform(
                                    async move {
                                        engine.load_page_with_progress(url, tab_id).await
                                    },
                                    move |result| Message::PageLoaded(tab_id, result)
                                ),
                            ]);
                        }
                        
                        Command::none()
                    }
                    Err(e) => {
                        log::error!("❌ Invalid URL: {} - {}", url_str, e);
                        
                        // Show user-friendly error
                        if let Some(active_tab) = self.tab_manager.get_tab_states().iter().find(|tab| tab.is_active) {
                            let error = LoadingError {
                                error_type: ErrorType::Content,
                                message: format!("Invalid URL: {}", e),
                                url: url_str,
                                timestamp: std::time::SystemTime::now(),
                                retry_possible: true,
                            };
                            self.error_states.insert(active_tab.id, error.message.clone());
                        }
                        
                        Command::none()
                    }
                }
            }
            
            Message::PageLoaded(tab_id, result) => {
                // Clear loading state
                self.loading_states.remove(&tab_id);
                
                match result {
                    Ok(page_data) => {
                        log::info!("✅ Page loaded successfully: {}, {} elements, {} bytes", 
                                   page_data.title, page_data.element_count, page_data.size_bytes);
                        
                        // Clear any error state
                        self.error_states.remove(&tab_id);
                        
                        // Update renderer with DOM and stylesheet if available
                        if let (Some(dom), Some(stylesheet)) = (&page_data.dom, &page_data.stylesheet) {
                            if let Err(e) = self.renderer.update_content(dom.clone(), stylesheet.clone()) {
                                log::warn!("Failed to update renderer: {}", e);
                            }
                        }
                        
                                                 // Update tab with loaded content
                         let tab_manager = self.tab_manager.clone();
                         let content = PageContent::Loaded {
                             url: page_data.url.clone(),
                             title: page_data.title.clone(),
                             content: page_data.content.clone(),
                             element_count: page_data.element_count,
                             size_bytes: page_data.size_bytes,
                         };
                        
                        return Command::perform(
                            async move {
                                let _ = tab_manager.update_page_content(tab_id, content).await;
                            },
                            {
                                let tab_id_copy = tab_id;
                                move |_| Message::LoadingStateUpdate(tab_id_copy, LoadingState::Idle)
                            }
                        );
                    }
                    Err(error) => {
                        log::error!("❌ Page loading failed: {} - {}", error.url, error.message);
                        
                        // Store error state for user feedback
                        self.error_states.insert(tab_id, error.message.clone());
                        
                                                 // Update tab with error content
                         let tab_manager = self.tab_manager.clone();
                         let error_content = PageContent::Error {
                             url: error.url.clone(),
                             error: error.message.clone(),
                         };
                        
                        return Command::perform(
                            async move {
                                let _ = tab_manager.update_page_content(tab_id, error_content).await;
                            },
                            {
                                let tab_id_copy = tab_id;
                                move |_| Message::LoadingStateUpdate(tab_id_copy, LoadingState::Idle)
                            }
                        );
                     }
                 }
             }
            
            Message::NewTab { tab_type, initial_url } => {
                log::info!("📑 Creating new tab: {:?}", tab_type);
                
                let tab_manager = self.tab_manager.clone();
                let url = initial_url.as_ref().map(|u| u.clone()).unwrap_or_else(|| "about:blank".to_string());
                let initial_url_copy = initial_url.clone(); // Clone for the closure
                
                return Command::perform(
                    async move {
                        tab_manager.open_tab(url.clone(), tab_type).await
                    },
                    move |result| match result {
                        Ok(tab_id) => {
                            log::info!("✅ Tab created successfully: {}", tab_id);
                            if let Some(url) = initial_url_copy {
                                Message::Navigate(url)
                            } else {
                                Message::LoadingStateUpdate(tab_id, LoadingState::Idle)
                            }
                        }
                        Err(e) => {
                            log::error!("❌ Failed to create tab: {}", e);
                            Message::InitializationError(format!("Failed to create tab: {}", e))
                        }
                    }
                );
            }
            
            Message::CloseTab(tab_id) => {
                log::info!("🗑️ Closing tab: {}", tab_id);
                
                // Clean up state
                self.error_states.remove(&tab_id);
                self.loading_states.remove(&tab_id);
                
                let tab_manager = self.tab_manager.clone();
                return Command::perform(
                    async move {
                        tab_manager.close_tab(tab_id).await
                    },
                    move |result| match result {
                        Ok(_) => {
                            log::info!("✅ Tab closed successfully");
                            Message::LoadingStateUpdate(tab_id, LoadingState::Idle) // Dummy message
                        }
                        Err(e) => {
                            log::error!("❌ Failed to close tab: {}", e);
                            Message::InitializationError(format!("Failed to close tab: {}", e))
                        }
                    }
                );
            }
            
            Message::SwitchTab(tab_id) => {
                log::info!("🔄 Switching to tab: {}", tab_id);
                
                let tab_manager = self.tab_manager.clone();
                let tab_id_copy = tab_id; // Copy the UUID
                return Command::perform(
                    async move {
                        tab_manager.switch_tab(tab_id_copy).await
                    },
                    move |result| match result {
                        Ok(_) => {
                            log::info!("✅ Tab switched successfully");
                            Message::LoadingStateUpdate(tab_id_copy, LoadingState::Idle) // Dummy message
                        }
                        Err(e) => {
                            log::error!("❌ Failed to switch tab: {}", e);
                            Message::InitializationError(format!("Tab switch error: {}", e))
                        }
                    }
                );
            }
            
            Message::UpdatePrivacy(level) => {
                log::info!("🔒 Updating privacy level to: {:?}", level);
                self.network_config.privacy_level = level;
                
                // TODO: Update engine configuration and reload if necessary
                Command::none()
            }
            
            Message::EngineInitialized(engine) => {
                log::info!("🎉 Engine initialized successfully");
                self.engine = Some(engine);
                Command::none()
            }
            
            Message::InitializationError(error) => {
                log::error!("💥 Initialization error: {}", error);
                // TODO: Show error in UI
                Command::none()
            }
            
            Message::LoadingStateUpdate(tab_id, state) => {
                log::debug!("📊 Loading state update for tab {}: {:?}", tab_id, state);
                self.loading_states.insert(tab_id, state);
                Command::none()
            }
            
            Message::ClearError(tab_id) => {
                log::info!("🧹 Clearing error for tab: {}", tab_id);
                self.error_states.remove(&tab_id);
                Command::none()
            }
            
            Message::RefreshTab => {
                log::info!("🔄 Refreshing current tab");
                
                if let Some(active_tab) = self.tab_manager.get_tab_states().iter().find(|tab| tab.is_active) {
                    // Get current URL from tab content
                    match &active_tab.content {
                        PageContent::Loaded { url, .. } |
                        PageContent::Loading { url } |
                        PageContent::Error { url, .. } => {
                            return self.update(Message::Navigate(url.clone()));
                        }
                        PageContent::Empty => {
                            // Nothing to refresh
                            return Command::none();
                        }
                    }
                }
                
                Command::none()
            }
            
            Message::StopLoading(tab_id) => {
                log::info!("⏹️ Stopping loading for tab: {}", tab_id);
                
                // Clear loading state
                self.loading_states.remove(&tab_id);
                
                // TODO: Cancel ongoing requests
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        self.ui.view(&self.tab_manager, &self.network_config, &self.renderer)
    }

    fn subscription(&self) -> Subscription<Message> {
        // TODO: Add subscriptions for real-time updates
        Subscription::none()
    }

    fn theme(&self) -> Theme {
        Theme::Dark // Privacy-focused dark theme by default
    }
}

impl CitadelBrowser {
    /// Normalize and validate URLs with security considerations
    fn normalize_url(&self, url_str: &str) -> String {
        let trimmed = url_str.trim();

        if trimmed.is_empty() {
            return "about:blank".to_string();
        }

        // If it's already a full URL, let it be.
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") || trimmed.starts_with("about:") || trimmed.starts_with("file://") {
            return trimmed.to_string();
        }

        // Check if it's a local file path.
        if let Ok(path) = std::fs::canonicalize(trimmed) {
            if let Ok(url) = Url::from_file_path(path) {
                return url.to_string();
            }
        }
        
        // If not a file, treat as a search query or domain.
        if !trimmed.contains('.') && !trimmed.contains('/') {
            return format!("https://duckduckgo.com/?q={}", urlencoding::encode(trimmed));
        }

        // Default to https for things that look like domains.
        format!("https://{}", trimmed)
    }
}

/// Extract title from HTML content (utility function)
fn extract_title(html: &str) -> Option<String> {
    if let Some(start) = html.find("<title>") {
        if let Some(end) = html[start + 7..].find("</title>") {
            let title = &html[start + 7..start + 7 + end];
            return Some(title.trim().to_string());
        }
    }
    None
}