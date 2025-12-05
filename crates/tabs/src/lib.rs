//! Citadel Tab Management System
//! 
//! This module implements privacy-focused tab management with ZKVM isolation.
//! Each tab runs in its own Zero-Knowledge Virtual Machine, providing cryptographic
//! guarantees of isolation between tabs.

mod ui;
mod send_safe_tab_manager;
pub mod zkvm_renderer;

use std::sync::Arc;
use parking_lot::RwLock as ParkingLotRwLock;
use tokio::sync::RwLock;
use thiserror::Error;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use citadel_zkvm::{ZkVm, Channel, ChannelMessage};

// Re-export UI components
pub use ui::{TabBar, Message as TabMessage};

// Re-export the Send-safe tab manager for browser use
pub use send_safe_tab_manager::SendSafeTabManager;
// Re-export zkvm_renderer types
pub use zkvm_renderer::RenderedContent;

/// Errors that can occur during tab operations
#[derive(Error, Debug)]
pub enum TabError {
    #[error("Tab not found: {0}")]
    NotFound(Uuid),
    
    #[error("VM error: {0}")]
    VmError(#[from] citadel_zkvm::ZkVmError),
    
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    
    #[error("Persistence error: {0}")]
    PersistenceError(String),
}

/// Result type for tab operations
pub type TabResult<T> = Result<T, TabError>;

/// Type of tab (Ephemeral or Container)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TabType {
    /// Ephemeral tab - no persistence, maximum privacy
    Ephemeral,
    /// Container tab - persistent state with controlled isolation
    Container {
        /// Container identifier
        container_id: Uuid,
    },
}

/// Page content state for tabs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PageContent {
    /// Page is loading
    Loading { url: String },
    /// Page loaded successfully
    Loaded { 
        url: String,
        title: String,
        content: String,
        element_count: usize,
        size_bytes: usize,
    },
    /// Page failed to load
    Error { 
        url: String,
        error: String,
    },
    /// Empty tab
    Empty,
}

/// Tab state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabState {
    /// Tab identifier
    pub id: Uuid,
    /// Tab title
    pub title: String,
    /// Tab URL
    pub url: String,
    /// Tab type
    pub tab_type: TabType,
    /// Whether the tab is currently active
    pub is_active: bool,
    /// Tab creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Page content state
    pub content: PageContent,
}

/// Represents a browser tab with ZKVM isolation
pub struct Tab {
    /// Tab state
    state: Arc<RwLock<TabState>>,
    /// The ZKVM instance for this tab
    vm: Arc<ZkVm>,
    /// Communication channel to the VM
    channel: Channel,
}

/// Simple tab implementation for browser compatibility
pub struct SimpleTab {
    /// Unique identifier for the tab
    id: Uuid,
    /// Current URL of the tab
    url: Arc<ParkingLotRwLock<String>>,
    /// Tab title
    title: Arc<ParkingLotRwLock<String>>,
    /// Whether the tab is currently loading
    is_loading: Arc<ParkingLotRwLock<bool>>,
}

impl SimpleTab {
    /// Create a new simple tab with the given URL
    pub fn new(url: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            url: Arc::new(ParkingLotRwLock::new(url)),
            title: Arc::new(ParkingLotRwLock::new(String::new())),
            is_loading: Arc::new(ParkingLotRwLock::new(false)),
        }
    }

    /// Get the tab's ID
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Get the current URL
    pub fn url(&self) -> String {
        self.url.read().clone()
    }

    /// Set a new URL for the tab
    pub fn set_url(&self, new_url: String) {
        *self.url.write() = new_url;
    }

    /// Get the tab's title
    pub fn title(&self) -> String {
        self.title.read().clone()
    }

    /// Set the tab's title
    pub fn set_title(&self, new_title: String) {
        *self.title.write() = new_title;
    }

    /// Check if the tab is currently loading
    pub fn is_loading(&self) -> bool {
        *self.is_loading.read()
    }

    /// Set the loading state
    pub fn set_loading(&self, loading: bool) {
        *self.is_loading.write() = loading;
    }
}

/// Simple tab manager for browser compatibility
pub struct SimpleTabManager {
    /// All open tabs
    tabs: Arc<ParkingLotRwLock<std::collections::HashMap<Uuid, Arc<SimpleTab>>>>,
    /// Currently active tab ID
    active_tab: Arc<ParkingLotRwLock<Option<Uuid>>>,
}

impl SimpleTabManager {
    /// Create a new simple tab manager
    pub fn new() -> Self {
        Self {
            tabs: Arc::new(ParkingLotRwLock::new(std::collections::HashMap::new())),
            active_tab: Arc::new(ParkingLotRwLock::new(None)),
        }
    }

    /// Create a new tab and return its ID
    pub fn create_tab(&self, url: String) -> Uuid {
        let tab = Arc::new(SimpleTab::new(url));
        let id = tab.id();
        
        let mut tabs = self.tabs.write();
        tabs.insert(id, tab);
        
        // If this is the first tab, make it active
        if tabs.len() == 1 {
            *self.active_tab.write() = Some(id);
        }
        
        id
    }

    /// Close a tab by ID
    pub fn close_tab(&self, id: Uuid) -> bool {
        let mut tabs = self.tabs.write();
        let mut active_tab = self.active_tab.write();
        
        if tabs.remove(&id).is_some() {
            // If we closed the active tab, activate the next available tab
            if active_tab.map_or(false, |active_id| active_id == id) {
                *active_tab = tabs.keys().next().copied();
            }
            true
        } else {
            false
        }
    }

    /// Get a reference to a tab by ID
    pub fn get_tab(&self, id: Uuid) -> Option<Arc<SimpleTab>> {
        self.tabs.read().get(&id).cloned()
    }

    /// Get the active tab
    pub fn active_tab(&self) -> Option<Arc<SimpleTab>> {
        let active_id = *self.active_tab.read();
        active_id.and_then(|id| self.get_tab(id))
    }

    /// Set the active tab
    pub fn set_active_tab(&self, id: Uuid) -> bool {
        if self.tabs.read().contains_key(&id) {
            *self.active_tab.write() = Some(id);
            true
        } else {
            false
        }
    }

    /// Get all open tabs
    pub fn all_tabs(&self) -> Vec<Arc<SimpleTab>> {
        self.tabs.read().values().cloned().collect()
    }

    /// Get the number of open tabs
    pub fn tab_count(&self) -> usize {
        self.tabs.read().len()
    }
}

impl Default for SimpleTabManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages all browser tabs
pub struct TabManager {
    /// All active tabs
    tabs: Arc<ParkingLotRwLock<Vec<Tab>>>,
    /// Currently active tab ID
    active_tab: Arc<ParkingLotRwLock<Option<Uuid>>>,
}

impl Tab {
    /// Create a new tab
    pub async fn new(url: String, tab_type: TabType) -> TabResult<(Self, Channel)> {
        // Create a new ZKVM instance for this tab
        let (vm, _host_channel) = ZkVm::new().await?;
        
        // Create a channel pair for tab-host communication
        let (tab_channel, _host_channel) = Channel::new()?;
        
        // Create another channel pair for renderer communication
        let (renderer_vm_channel, renderer_host_channel) = Channel::new()?;
        
        let state = TabState {
            id: Uuid::new_v4(),
            title: String::new(),
            url: url.clone(),
            tab_type,
            is_active: false,
            created_at: chrono::Utc::now(),
            content: PageContent::Loading { url },
        };
        
        let tab_id = state.id;
        
        let tab = Self {
            state: Arc::new(RwLock::new(state)),
            vm: Arc::new(vm),
            channel: tab_channel,
        };
        
        // Start the VM
        tab.vm.start().await?;
        
        // Spawn the ZKVM renderer task
        tokio::spawn(async move {
            log::info!("Starting ZKVM renderer for tab {}", tab_id);
            if let Err(e) = zkvm_renderer::spawn_zkvm_renderer(renderer_vm_channel).await {
                log::error!("ZKVM renderer error for tab {}: {}", tab_id, e);
            }
        });
        
        Ok((tab, renderer_host_channel))
    }
    
    /// Convert tab type (with user warning)
    pub async fn convert_to_container(&self) -> TabResult<()> {
        let mut state = self.state.write().await;
        
        // Only allow conversion from Ephemeral to Container
        match state.tab_type {
            TabType::Ephemeral => {
                let container_id = Uuid::new_v4();
                state.tab_type = TabType::Container { container_id };
                
                // Send conversion message to VM
                self.channel.send(ChannelMessage::Control {
                    command: "convert_to_container".into(),
                    params: serde_json::json!({
                        "container_id": container_id.to_string()
                    }).to_string(),
                }).await?;
                
                Ok(())
            }
            TabType::Container { .. } => {
                Err(TabError::InvalidOperation(
                    "Tab is already a container".into()
                ))
            }
        }
    }
    
    /// Load a URL in the tab
    pub async fn load_url(&self, url: String) -> TabResult<()> {
        let mut state = self.state.write().await;
        state.url = url.clone();
        
        // Send URL load message to VM
        self.channel.send(ChannelMessage::ResourceRequest {
            url,
            headers: vec![],
        }).await?;
        
        Ok(())
    }
    
    /// Close the tab
    pub async fn close(&self) -> TabResult<()> {
        // Terminate the VM
        self.vm.terminate().await?;
        
        // If this is a container tab, persist its state
        let state = self.state.read().await;
        if let TabType::Container { container_id } = state.tab_type {
            self.persist_container_state(container_id).await?;
        }
        
        Ok(())
    }
    
    /// Persist container state
    async fn persist_container_state(&self, _container_id: Uuid) -> TabResult<()> {
        // TODO: Implement container state persistence
        Ok(())
    }
}

impl TabManager {
    /// Create a new tab manager
    /// NOTE: This implementation is currently disabled due to Send safety issues.
    /// Use SendSafeTabManager instead for browser integration.
    pub fn new() -> Self {
        Self {
            tabs: Arc::new(ParkingLotRwLock::new(Vec::new())),
            active_tab: Arc::new(ParkingLotRwLock::new(None)),
        }
    }
    
    /// Get all tab states (simplified version for compatibility)
    pub fn get_tab_states(&self) -> Vec<TabState> {
        // Return empty for now - the actual implementation requires async context
        Vec::new()
    }
    
    /// Get the number of open tabs
    pub fn tab_count(&self) -> usize {
        self.tabs.read().len()
    }
    
    /// Get the currently active tab ID
    pub fn get_active_tab_id(&self) -> Option<Uuid> {
        *self.active_tab.read()
    }
    
    /// Set the active tab
    pub fn set_active_tab(&self, tab_id: Option<Uuid>) -> bool {
        let mut active_tab = self.active_tab.write();
        *active_tab = tab_id;
        true
    }
    
    /// Check if there are any tabs open
    pub fn has_tabs(&self) -> bool {
        self.tab_count() > 0
    }
}

// NOTE: The full TabManager implementation is disabled to avoid Send safety issues.
// Use SendSafeTabManager for production browser code.

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tab_state_creation() {
        let tab_state = TabState {
            id: Uuid::new_v4(),
            title: "Test Tab".to_string(),
            url: "https://example.com".to_string(),
            tab_type: TabType::Ephemeral,
            is_active: false,
            created_at: chrono::Utc::now(),
            content: PageContent::Loading { url: "https://example.com".to_string() },
        };
        
        assert_eq!(tab_state.url, "https://example.com");
        assert_eq!(tab_state.title, "Test Tab");
        assert!(!tab_state.is_active);
        assert!(matches!(tab_state.content, PageContent::Loading { .. }));
    }
    
    #[test]
    fn test_page_content_variants() {
        let loading = PageContent::Loading { url: "https://example.com".to_string() };
        let loaded = PageContent::Loaded { 
            url: "https://example.com".to_string(),
            title: "Example".to_string(),
            content: "Test content".to_string(),
            element_count: 5,
            size_bytes: 1024,
        };
        let error = PageContent::Error { 
            url: "https://example.com".to_string(),
            error: "Network error".to_string(),
        };
        let empty = PageContent::Empty;
        
        assert!(matches!(loading, PageContent::Loading { .. }));
        assert!(matches!(loaded, PageContent::Loaded { .. }));
        assert!(matches!(error, PageContent::Error { .. }));
        assert!(matches!(empty, PageContent::Empty));
    }
} 
