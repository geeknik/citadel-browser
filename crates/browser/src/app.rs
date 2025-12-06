//! Enhanced Citadel Browser application with comprehensive error handling and user feedback
//! 
//! This module implements the main browser application with security-first design,
//! ZKVM tab isolation, and privacy-preserving features.

use std::sync::Arc;
use std::collections::HashMap;
use tokio::runtime::Runtime;
use iced::{Application, Command, Element, Subscription, Theme};
use iced::keyboard::Key;
use url::Url;

use crate::ui::{CitadelUI, UIMessage};
use crate::engine::BrowserEngine;
use crate::renderer::{CitadelRenderer, FormMessage, FormSubmission};
use crate::zkvm_receiver;
// WORKAROUND: Use explicit paths to break circular import
// Import performance types directly to avoid circular dependency with lib.rs re-exports
use citadel_tabs::{SendSafeTabManager as TabManager, TabType, PageContent};
use citadel_networking::{NetworkConfig, PrivacyLevel};
use citadel_security::SecurityContext;
use citadel_parser::{Dom, CitadelStylesheet};

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
    /// Channel for receiving ZKVM output
    zkvm_output_sender: tokio::sync::mpsc::UnboundedSender<zkvm_receiver::ZkVmOutput>,
    zkvm_output_receiver: Option<tokio::sync::mpsc::UnboundedReceiver<zkvm_receiver::ZkVmOutput>>,
    /// Store DOM and stylesheet per tab for renderer state
    tab_render_data: HashMap<uuid::Uuid, (Arc<Dom>, Arc<CitadelStylesheet>)>,
    /// Viewport information and state
    viewport_info: ViewportInfo,
    /// Performance monitoring system (TODO: Fix circular import)
    // performance_monitor: Arc<PerformanceMonitor>,
    /// Memory cleanup timer
    last_memory_cleanup: std::time::Instant,
    /// Scroll state per tab
    tab_scroll_states: HashMap<uuid::Uuid, ScrollState>,
    /// Zoom level per tab
    tab_zoom_levels: HashMap<uuid::Uuid, ZoomLevel>,
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

/// Zoom level for browser content
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZoomLevel {
    Percent50,
    Percent75,
    Percent100,
    Percent125,
    Percent150,
    Percent200,
}

impl ZoomLevel {
    pub fn as_factor(&self) -> f32 {
        match self {
            ZoomLevel::Percent50 => 0.5,
            ZoomLevel::Percent75 => 0.75,
            ZoomLevel::Percent100 => 1.0,
            ZoomLevel::Percent125 => 1.25,
            ZoomLevel::Percent150 => 1.5,
            ZoomLevel::Percent200 => 2.0,
        }
    }
    
    pub fn next(&self) -> Option<ZoomLevel> {
        match self {
            ZoomLevel::Percent50 => Some(ZoomLevel::Percent75),
            ZoomLevel::Percent75 => Some(ZoomLevel::Percent100),
            ZoomLevel::Percent100 => Some(ZoomLevel::Percent125),
            ZoomLevel::Percent125 => Some(ZoomLevel::Percent150),
            ZoomLevel::Percent150 => Some(ZoomLevel::Percent200),
            ZoomLevel::Percent200 => None,
        }
    }
    
    pub fn previous(&self) -> Option<ZoomLevel> {
        match self {
            ZoomLevel::Percent50 => None,
            ZoomLevel::Percent75 => Some(ZoomLevel::Percent50),
            ZoomLevel::Percent100 => Some(ZoomLevel::Percent75),
            ZoomLevel::Percent125 => Some(ZoomLevel::Percent100),
            ZoomLevel::Percent150 => Some(ZoomLevel::Percent125),
            ZoomLevel::Percent200 => Some(ZoomLevel::Percent150),
        }
    }
    
    pub fn as_percentage(&self) -> u16 {
        match self {
            ZoomLevel::Percent50 => 50,
            ZoomLevel::Percent75 => 75,
            ZoomLevel::Percent100 => 100,
            ZoomLevel::Percent125 => 125,
            ZoomLevel::Percent150 => 150,
            ZoomLevel::Percent200 => 200,
        }
    }
}

/// Viewport information for scrolling and responsive design
#[derive(Debug, Clone)]
pub struct ViewportInfo {
    pub width: f32,
    pub height: f32,
    pub device_pixel_ratio: f32,
    pub zoom_level: ZoomLevel,
}

impl Default for ViewportInfo {
    fn default() -> Self {
        Self {
            width: 800.0,
            height: 600.0,
            device_pixel_ratio: 1.0,
            zoom_level: ZoomLevel::Percent100,
        }
    }
}

/// Scroll position and state
#[derive(Debug, Clone, Default)]
pub struct ScrollState {
    pub x: f32,
    pub y: f32,
    pub max_x: f32,
    pub max_y: f32,
    pub viewport_width: f32,
    pub viewport_height: f32,
}

impl ScrollState {
    pub fn can_scroll_up(&self) -> bool {
        self.y > 0.0
    }
    
    pub fn can_scroll_down(&self) -> bool {
        self.y < self.max_y
    }
    
    pub fn can_scroll_left(&self) -> bool {
        self.x > 0.0
    }
    
    pub fn can_scroll_right(&self) -> bool {
        self.x < self.max_x
    }
    
    pub fn scroll_by(&mut self, dx: f32, dy: f32) {
        self.x = (self.x + dx).clamp(0.0, self.max_x);
        self.y = (self.y + dy).clamp(0.0, self.max_y);
    }
    
    pub fn scroll_to(&mut self, x: f32, y: f32) {
        self.x = x.clamp(0.0, self.max_x);
        self.y = y.clamp(0.0, self.max_y);
    }
    
    pub fn page_up(&mut self) {
        let page_height = self.viewport_height * 0.9; // 90% of viewport
        self.scroll_by(0.0, -page_height);
    }
    
    pub fn page_down(&mut self) {
        let page_height = self.viewport_height * 0.9; // 90% of viewport
        self.scroll_by(0.0, page_height);
    }
    
    pub fn home(&mut self) {
        self.scroll_to(0.0, 0.0);
    }
    
    pub fn end(&mut self) {
        self.scroll_to(0.0, self.max_y);
    }
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
    /// ZKVM output received
    ZkVmOutput(zkvm_receiver::ZkVmOutput),
    /// Tab opened, need to setup channel
    TabOpened { 
        tab_id: uuid::Uuid,
        initial_url: Option<String> 
    },
    /// Form interaction messages
    FormInteraction(FormMessage),
    /// Form submission request
    FormSubmit(FormSubmission),
    /// Viewport and scrolling messages
    ZoomIn,
    ZoomOut,
    ZoomReset,
    ZoomToLevel(ZoomLevel),
    ScrollUp,
    ScrollDown,
    ScrollLeft,
    ScrollRight,
    PageUp,
    PageDown,
    Home,
    End,
    ScrollTo { x: f32, y: f32 },
    ViewportResized { width: f32, height: f32 },
    MouseWheel { delta_x: f32, delta_y: f32 },
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
        let security_context = Arc::new(SecurityContext::new(10));
        
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
        
        // Create ZKVM output channel
        let (zkvm_output_sender, zkvm_output_receiver) = tokio::sync::mpsc::unbounded_channel();
        
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
            zkvm_output_sender,
            zkvm_output_receiver: Some(zkvm_output_receiver),
            tab_render_data: HashMap::new(),
            viewport_info: ViewportInfo::default(),
            tab_scroll_states: HashMap::new(),
            tab_zoom_levels: HashMap::new(),
            // performance_monitor,
            last_memory_cleanup: std::time::Instant::now(),
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
        // Periodic memory cleanup and performance monitoring
        self.periodic_memory_cleanup();
        
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
                        
                        // Route content through ZKVM for proper tab isolation
                        if let (Some(dom), Some(stylesheet)) = (&page_data.dom, &page_data.stylesheet) {
                            log::info!("🔒 Routing content through ZKVM for tab isolation: {}", tab_id);
                            
                            // Store DOM and stylesheet for this tab
                            self.tab_render_data.insert(tab_id, (dom.clone(), stylesheet.clone()));
                            
                            // Send content to ZKVM for isolated processing
                            let zkvm_content = citadel_tabs::PageContent::Loaded {
                                url: page_data.url.clone(),
                                title: page_data.title.clone(),
                                content: page_data.content.clone(),
                                element_count: page_data.element_count,
                                size_bytes: page_data.size_bytes,
                            };
                            
                            // Send to ZKVM channel for isolated processing
                            match citadel_zkvm::Channel::new() {
                                Ok((vm_channel, _host_channel)) => {
                                    // Send rendering command to ZKVM
                                    let message = citadel_zkvm::ChannelMessage::Control {
                                        command: "render_content".to_string(),
                                        params: serde_json::to_string(&zkvm_content).unwrap_or_default(),
                                    };
                                    
                                    // Process in isolated environment
                                    tokio::spawn(async move {
                                        if let Err(e) = vm_channel.send(message).await {
                                            log::error!("Failed to send to ZKVM: {}", e);
                                            return Err(e.to_string());
                                        }
                                        Ok(())
                                    });
                                    
                                    // For now, also update renderer directly (will be replaced by ZKVM output)
                                    match self.renderer.update_content(dom.clone(), stylesheet.clone()) {
                                        Ok(_) => {
                                            log::info!("✅ Content processed through ZKVM isolation boundary");
                                        },
                                        Err(e) => {
                                            log::error!("❌ Failed to process content through ZKVM: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::error!("❌ ZKVM channel creation failed: {}", e);
                                    // Fallback to direct rendering for now
                                    if let Err(e) = self.renderer.update_content(dom.clone(), stylesheet.clone()) {
                                        log::error!("❌ Fallback renderer update failed: {}", e);
                                    }
                                }
                            }
                        } else {
                            log::error!("❌ CRITICAL: No DOM or stylesheet available for ZKVM processing");
                            log::error!("  DOM present: {}", page_data.dom.is_some());
                            log::error!("  Stylesheet present: {}", page_data.stylesheet.is_some());
                        }
                        
                                                 // Initialize or update scroll state for this tab
                        self.initialize_tab_scroll_state(tab_id);
                        self.update_scroll_state_for_content(tab_id);
                        
                        // Update tab with loaded content
                         let tab_manager = self.tab_manager.clone();
                         let content = PageContent::Loaded {
                             url: page_data.url.clone(),
                             title: page_data.title.clone(),
                             content: page_data.content.clone(),
                             element_count: page_data.element_count,
                             size_bytes: page_data.size_bytes,
                         };
                        
                        Command::perform(
                            async move {
                                let _ = tab_manager.update_page_content(tab_id, content).await;
                            },
                            {
                                let tab_id_copy = tab_id;
                                move |_| Message::LoadingStateUpdate(tab_id_copy, LoadingState::Idle)
                            }
                        )
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
                        
                        Command::perform(
                            async move {
                                let _ = tab_manager.update_page_content(tab_id, error_content).await;
                            },
                            {
                                let tab_id_copy = tab_id;
                                move |_| Message::LoadingStateUpdate(tab_id_copy, LoadingState::Idle)
                            }
                        )
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
                            Message::TabOpened { 
                                tab_id, 
                                initial_url: initial_url_copy 
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
                self.tab_render_data.remove(&tab_id);
                self.tab_scroll_states.remove(&tab_id);
                self.tab_zoom_levels.remove(&tab_id);
                
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
                
                // Update renderer with the stored DOM/stylesheet for this tab
                if let Some((dom, stylesheet)) = self.tab_render_data.get(&tab_id) {
                    match self.renderer.update_content(dom.clone(), stylesheet.clone()) {
                        Ok(_) => {
                            log::info!("✅ Renderer updated with content for tab {}", tab_id);
                        },
                        Err(e) => {
                            log::warn!("Failed to update renderer when switching tab: {}", e);
                        }
                    }
                } else {
                    log::info!("No render data stored for tab {}", tab_id);
                }
                
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
            
            Message::ZkVmOutput(output) => {
                use zkvm_receiver::ZkVmOutput;
                
                match output {
                    ZkVmOutput::RenderedContent { tab_id, content } => {
                        log::info!("📦 Received rendered content from ZKVM for tab {}", tab_id);
                        log::debug!("🧩 ZKVM payload length: {} bytes", content.html.len());
                        
                        // Update the renderer with the sanitized content
                        // In a real implementation, we would use the rendered content
                        // to update the display
                        
                        // Clear loading state
                        self.loading_states.insert(tab_id, LoadingState::Idle);
                        
                        Command::none()
                    }
                    ZkVmOutput::Error { tab_id, error } => {
                        log::error!("❌ ZKVM error for tab {}: {}", tab_id, error);
                        self.error_states.insert(tab_id, error);
                        self.loading_states.insert(tab_id, LoadingState::Idle);
                        
                        Command::none()
                    }
                }
            }
            
            Message::TabOpened { tab_id, initial_url } => {
                log::info!("🔗 Tab {} opened", tab_id);
                
                // TODO: Get channel from tab manager and setup receiver
                // For now, just navigate if URL provided
                
                // Navigate if initial URL provided
                if let Some(url) = initial_url {
                    self.update(Message::Navigate(url))
                } else {
                    Command::none()
                }
            }
            
            Message::FormInteraction(form_message) => {
                log::info!("📝 Form interaction: {:?}", form_message);
                
                // Handle form interaction in the renderer
                self.renderer.handle_form_message(form_message.clone());
                
                // Check if this triggers a form submission
                if let Some(submission) = self.renderer.get_form_state().pending_submission.clone() {
                    return self.update(Message::FormSubmit(submission));
                }
                
                Command::none()
            }
            
            Message::FormSubmit(submission) => {
                log::info!("📤 Form submission request: {} -> {}", submission.form_id, submission.action);
                
                // Validate form submission security
                if !self.validate_form_security(&submission) {
                    log::warn!("🛡️ Form submission blocked for security reasons");
                    return Command::none();
                }
                
                // Process form submission through the engine
                if let Some(engine) = &self.engine {
                    let engine_clone = engine.clone();
                    return Command::perform(
                        async move {
                            engine_clone.submit_form(submission).await
                        },
                        |result| match result {
                            Ok(response_url) => {
                                log::info!("✅ Form submitted successfully, navigating to response");
                                Message::Navigate(response_url)
                            }
                            Err(e) => {
                                log::error!("❌ Form submission failed: {}", e);
                                Message::InitializationError(format!("Form submission failed: {}", e))
                            }
                        }
                    );
                } else {
                    log::error!("❌ Cannot submit form: Engine not initialized");
                    return Command::none();
                }
            }
            
            // Viewport and scrolling message handlers
            Message::ZoomIn => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let current_zoom = self.tab_zoom_levels.get(&active_tab).copied().unwrap_or(ZoomLevel::Percent100);
                    if let Some(new_zoom) = current_zoom.next() {
                        self.tab_zoom_levels.insert(active_tab, new_zoom);
                        self.renderer.set_zoom_level(new_zoom.as_factor());
                        log::info!("🔍 Zoomed in to {}%", new_zoom.as_percentage());
                        
                        // Update viewport and recompute layout if needed
                        self.update_viewport_for_zoom(new_zoom);
                    }
                }
                Command::none()
            }
            
            Message::ZoomOut => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let current_zoom = self.tab_zoom_levels.get(&active_tab).copied().unwrap_or(ZoomLevel::Percent100);
                    if let Some(new_zoom) = current_zoom.previous() {
                        self.tab_zoom_levels.insert(active_tab, new_zoom);
                        self.renderer.set_zoom_level(new_zoom.as_factor());
                        log::info!("🔍 Zoomed out to {}%", new_zoom.as_percentage());
                        
                        // Update viewport and recompute layout if needed
                        self.update_viewport_for_zoom(new_zoom);
                    }
                }
                Command::none()
            }
            
            Message::ZoomReset => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    self.tab_zoom_levels.insert(active_tab, ZoomLevel::Percent100);
                    self.renderer.set_zoom_level(1.0);
                    log::info!("🔍 Reset zoom to 100%");
                    
                    // Update viewport and recompute layout
                    self.update_viewport_for_zoom(ZoomLevel::Percent100);
                }
                Command::none()
            }
            
            Message::ZoomToLevel(zoom_level) => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    self.tab_zoom_levels.insert(active_tab, zoom_level);
                    self.renderer.set_zoom_level(zoom_level.as_factor());
                    log::info!("🔍 Set zoom to {}%", zoom_level.as_percentage());
                    
                    // Update viewport and recompute layout
                    self.update_viewport_for_zoom(zoom_level);
                }
                Command::none()
            }
            
            Message::ScrollUp => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.scroll_by(0.0, -50.0); // Scroll up by 50px
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("⬆️ Scrolled up to ({}, {})", scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
            
            Message::ScrollDown => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.scroll_by(0.0, 50.0); // Scroll down by 50px
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("⬇️ Scrolled down to ({}, {})", scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
            
            Message::ScrollLeft => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.scroll_by(-50.0, 0.0); // Scroll left by 50px
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("⬅️ Scrolled left to ({}, {})", scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
            
            Message::ScrollRight => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.scroll_by(50.0, 0.0); // Scroll right by 50px
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("➡️ Scrolled right to ({}, {})", scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
            
            Message::PageUp => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.page_up();
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("📄⬆️ Page up to ({}, {})", scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
            
            Message::PageDown => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.page_down();
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("📄⬇️ Page down to ({}, {})", scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
            
            Message::Home => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.home();
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("🏠 Scrolled to home (0, 0)");
                }
                Command::none()
            }
            
            Message::End => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.end();
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("🔚 Scrolled to end ({}, {})", scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
            
            Message::ScrollTo { x, y } => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    scroll_state.scroll_to(x, y);
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    log::debug!("📍 Scrolled to ({}, {})", scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
            
            Message::ViewportResized { width, height } => {
                log::info!("📐 Viewport resized to {}x{}", width, height);
                self.viewport_info.width = width;
                self.viewport_info.height = height;
                
                // Update renderer viewport
                self.renderer.update_viewport_size(width, height);
                
                // Update scroll states for all tabs
                let content_size = self.renderer.get_content_size();
                for scroll_state in self.tab_scroll_states.values_mut() {
                    scroll_state.viewport_width = width;
                    scroll_state.viewport_height = height;
                    
                    // Recompute scroll bounds with new viewport
                    scroll_state.max_x = (content_size.width - scroll_state.viewport_width).max(0.0);
                    scroll_state.max_y = (content_size.height - scroll_state.viewport_height).max(0.0);
                }
                
                Command::none()
            }
            
            Message::MouseWheel { delta_x, delta_y } => {
                if let Some(active_tab) = self.get_active_tab_id() {
                    let scroll_state = self.tab_scroll_states.entry(active_tab).or_default();
                    
                    // Apply mouse wheel sensitivity
                    let sensitivity = 3.0;
                    scroll_state.scroll_by(delta_x * sensitivity, delta_y * sensitivity);
                    self.renderer.set_scroll_position(scroll_state.x, scroll_state.y);
                    
                    log::debug!("🖱️ Mouse wheel scroll: delta=({}, {}), pos=({}, {})", 
                               delta_x, delta_y, scroll_state.x, scroll_state.y);
                }
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        self.ui.view(&self.tab_manager, &self.network_config, &self.renderer, &self.viewport_info, self.get_active_scroll_state())
    }

    fn subscription(&self) -> Subscription<Message> {
        // Subscribe to keyboard events for scrolling and zoom
        // For now, return a simple subscription - keyboard handling will be done through events
        Subscription::none()
    }

    fn theme(&self) -> Theme {
        Theme::Dark // Privacy-focused dark theme by default
    }
}

impl CitadelBrowser {
    /// Validate form submission security
    fn validate_form_security(&self, submission: &FormSubmission) -> bool {
        log::info!("🛡️ Validating form submission security for: {}", submission.action);
        
        // Block submissions to non-HTTPS URLs (except localhost for development)
        if !submission.action.starts_with("https://") &&
           !submission.action.starts_with("http://localhost") &&
           !submission.action.starts_with("http://127.0.0.1") &&
           submission.action != "#" {
            log::warn!("🛡️ Blocking insecure form submission to: {}", submission.action);
            return false;
        }
        
        // Validate HTTP method
        if !matches!(submission.method.as_str(), "GET" | "POST") {
            log::warn!("🛡️ Blocking form submission with unsupported method: {}", submission.method);
            return false;
        }
        
        // Check for potentially sensitive data in form fields
        for (field_name, field_value) in &submission.data {
            if field_name.to_lowercase().contains("password") && !submission.action.starts_with("https://") {
                log::warn!("🛡️ Blocking password submission over insecure connection");
                return false;
            }
            
            // Prevent extremely large form data (potential DoS)
            if field_value.len() > 1_000_000 { // 1MB limit per field
                log::warn!("🛡️ Blocking form submission with oversized field: {} ({} bytes)", field_name, field_value.len());
                return false;
            }
        }
        
        log::info!("✅ Form submission security validation passed");
        true
    }
    
    /// Get the active tab ID
    fn get_active_tab_id(&self) -> Option<uuid::Uuid> {
        self.tab_manager.get_tab_states()
            .iter()
            .find(|tab| tab.is_active)
            .map(|tab| tab.id)
    }
    
    /// Get the active tab's scroll state
    fn get_active_scroll_state(&self) -> Option<&ScrollState> {
        self.get_active_tab_id()
            .and_then(|tab_id| self.tab_scroll_states.get(&tab_id))
    }
    
    /// Update viewport for zoom changes
    fn update_viewport_for_zoom(&mut self, zoom_level: ZoomLevel) {
        self.viewport_info.zoom_level = zoom_level;
        
        // Calculate effective viewport size with zoom
        let effective_width = self.viewport_info.width / zoom_level.as_factor();
        let effective_height = self.viewport_info.height / zoom_level.as_factor();
        
        // Update renderer with new effective viewport
        self.renderer.update_viewport_size(effective_width, effective_height);
        
        // Update scroll bounds for active tab
        if let Some(active_tab) = self.get_active_tab_id() {
            if let Some(scroll_state) = self.tab_scroll_states.get_mut(&active_tab) {
                scroll_state.viewport_width = effective_width;
                scroll_state.viewport_height = effective_height;
                
                // Get content bounds from renderer
                let content_size = self.renderer.get_content_size();
                scroll_state.max_x = (content_size.width - scroll_state.viewport_width).max(0.0);
                scroll_state.max_y = (content_size.height - scroll_state.viewport_height).max(0.0);
                
                // Ensure scroll position is still valid after zoom
                scroll_state.scroll_to(scroll_state.x, scroll_state.y);
            }
        }
    }
    
    
    /// Initialize scroll state for a new tab
    fn initialize_tab_scroll_state(&mut self, tab_id: uuid::Uuid) {
        let mut scroll_state = ScrollState::default();
        scroll_state.viewport_width = self.viewport_info.width;
        scroll_state.viewport_height = self.viewport_info.height;
        
        // Get content bounds from renderer
        let content_size = self.renderer.get_content_size();
        scroll_state.max_x = (content_size.width - scroll_state.viewport_width).max(0.0);
        scroll_state.max_y = (content_size.height - scroll_state.viewport_height).max(0.0);
        
        self.tab_scroll_states.insert(tab_id, scroll_state);
        self.tab_zoom_levels.insert(tab_id, ZoomLevel::Percent100);
    }
    
    /// Update scroll state when content changes
    fn update_scroll_state_for_content(&mut self, tab_id: uuid::Uuid) {
        if let Some(scroll_state) = self.tab_scroll_states.get_mut(&tab_id) {
            // Get content bounds from renderer
            let content_size = self.renderer.get_content_size();
            scroll_state.max_x = (content_size.width - scroll_state.viewport_width).max(0.0);
            scroll_state.max_y = (content_size.height - scroll_state.viewport_height).max(0.0);
            
            // Ensure current scroll position is still valid
            scroll_state.scroll_to(scroll_state.x, scroll_state.y);
        }
    }
    
    /// Handle keyboard shortcuts for scrolling and zoom
    pub fn handle_keyboard_event(&mut self, key: &iced::keyboard::Key, modifiers: iced::keyboard::Modifiers) -> Command<Message> {
        match (key.as_ref(), modifiers.control()) {
            // Zoom shortcuts
            (Key::Character("=") | Key::Character("+"), true) => Command::perform(async {}, |_| Message::ZoomIn),
            (Key::Character("-"), true) => Command::perform(async {}, |_| Message::ZoomOut),
            (Key::Character("0"), true) => Command::perform(async {}, |_| Message::ZoomReset),
            
            // Scroll shortcuts
            (Key::Named(iced::keyboard::key::Named::ArrowUp), false) => Command::perform(async {}, |_| Message::ScrollUp),
            (Key::Named(iced::keyboard::key::Named::ArrowDown), false) => Command::perform(async {}, |_| Message::ScrollDown),
            (Key::Named(iced::keyboard::key::Named::ArrowLeft), false) => Command::perform(async {}, |_| Message::ScrollLeft),
            (Key::Named(iced::keyboard::key::Named::ArrowRight), false) => Command::perform(async {}, |_| Message::ScrollRight),
            (Key::Named(iced::keyboard::key::Named::PageUp), false) => Command::perform(async {}, |_| Message::PageUp),
            (Key::Named(iced::keyboard::key::Named::PageDown), false) => Command::perform(async {}, |_| Message::PageDown),
            (Key::Named(iced::keyboard::key::Named::Home), false) => Command::perform(async {}, |_| Message::Home),
            (Key::Named(iced::keyboard::key::Named::End), false) => Command::perform(async {}, |_| Message::End),
            
            _ => Command::none(),
        }
    }
    
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
    
    /// Perform periodic memory cleanup and performance monitoring
    fn periodic_memory_cleanup(&mut self) {
        let now = std::time::Instant::now();
        
        // Perform cleanup every 30 seconds
        if now.duration_since(self.last_memory_cleanup) >= std::time::Duration::from_secs(30) {
            self.last_memory_cleanup = now;
            
            // TODO: Fix circular import and re-enable performance monitoring
            // Check memory pressure and trigger cleanup if needed
            // let memory_pressure = self.performance_monitor.get_memory_pressure();
            
            // For now, just do basic cleanup
            self.cleanup_expired_data();
            
            // Also cleanup renderer caches
            self.renderer.force_cleanup("medium");
            
            // TODO: Re-enable memory metrics
            // self.update_memory_metrics();
        }
    }
    
    /// Clean up old tab render data
    fn cleanup_old_tab_data(&mut self) {
        let active_tabs: std::collections::HashSet<uuid::Uuid> = 
            self.tab_manager.get_tab_states().iter().map(|tab| tab.id).collect();
        
        // Remove render data for closed tabs
        self.tab_render_data.retain(|tab_id, _| active_tabs.contains(tab_id));
        self.tab_scroll_states.retain(|tab_id, _| active_tabs.contains(tab_id));
        self.tab_zoom_levels.retain(|tab_id, _| active_tabs.contains(tab_id));
        self.error_states.retain(|tab_id, _| active_tabs.contains(tab_id));
        self.loading_states.retain(|tab_id, _| active_tabs.contains(tab_id));
        
        log::debug!("Cleaned up render data for closed tabs");
    }
    
    /// Emergency memory cleanup for critical memory pressure
    fn emergency_memory_cleanup(&mut self) {
        log::warn!("Performing emergency memory cleanup");
        
        // Clear all caches and non-essential data
        self.tab_render_data.clear();
        self.error_states.clear();
        
        // Keep only active tab scroll state and zoom level
        if let Some(active_tab) = self.get_active_tab_id() {
            let active_scroll = self.tab_scroll_states.remove(&active_tab);
            let active_zoom = self.tab_zoom_levels.remove(&active_tab);
            
            self.tab_scroll_states.clear();
            self.tab_zoom_levels.clear();
            
            if let Some(scroll) = active_scroll {
                self.tab_scroll_states.insert(active_tab, scroll);
            }
            if let Some(zoom) = active_zoom {
                self.tab_zoom_levels.insert(active_tab, zoom);
            }
        } else {
            self.tab_scroll_states.clear();
            self.tab_zoom_levels.clear();
        }
        
        log::warn!("Emergency memory cleanup completed");
    }
    
    /// Clean up expired data during normal operation
    fn cleanup_expired_data(&mut self) {
        // This is called during normal operation to clean up expired data
        // Implementation would check timestamps and remove old data
        
        // For now, just ensure we don't have too many error states
        if self.error_states.len() > 50 {
            let active_tabs: std::collections::HashSet<uuid::Uuid> = 
                self.tab_manager.get_tab_states().iter().map(|tab| tab.id).collect();
            
            self.error_states.retain(|tab_id, _| active_tabs.contains(tab_id));
        }
        
        // Clean up old loading states - remove Idle states that are old
        // (We don't need to track timestamps for this simple case)
        // Just keep a reasonable number of idle states
        let idle_count = self.loading_states.values().filter(|state| matches!(state, LoadingState::Idle)).count();
        if idle_count > 10 {
            // Remove some idle states, keeping active ones
            let mut removed_count = 0;
            self.loading_states.retain(|_, loading_state| {
                if matches!(loading_state, LoadingState::Idle) && removed_count < idle_count - 5 {
                    removed_count += 1;
                    false
                } else {
                    true
                }
            });
        }
    }
    
    /// Update memory usage metrics
    fn update_memory_metrics(&mut self) {
        // Estimate memory usage of various components
        let tab_data_memory = self.tab_render_data.len() * 1024 * 1024; // Estimate 1MB per tab
        let scroll_state_memory = self.tab_scroll_states.len() * std::mem::size_of::<ScrollState>();
        let error_state_memory = self.error_states.len() * 1024; // Estimate 1KB per error
        let loading_state_memory = self.loading_states.len() * std::mem::size_of::<LoadingState>();
        
        let total_app_memory = tab_data_memory + scroll_state_memory + error_state_memory + loading_state_memory;
        log::debug!("📊 Estimated app memory usage: {} bytes", total_app_memory);
        
        // TODO: Re-enable performance monitoring
        // self.performance_monitor.update_memory_usage("app", total_app_memory);
    }
    
    /// Get performance statistics for debugging (TODO: Fix circular import)
    pub fn get_performance_stats(&self) -> String {
        // TODO: Re-enable performance monitoring once circular import is fixed
        format!(
            "Performance Stats (Basic):\n\
            Tab Data: {} entries\n\
            Scroll States: {} entries\n\
            Error States: {} entries\n\
            Loading States: {} entries\n",
            self.tab_render_data.len(),
            self.tab_scroll_states.len(),
            self.error_states.len(),
            self.loading_states.len()
        )
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
