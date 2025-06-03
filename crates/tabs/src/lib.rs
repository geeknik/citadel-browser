//! Citadel Tab Management System
//! 
//! This module implements privacy-focused tab management with ZKVM isolation.
//! Each tab runs in its own Zero-Knowledge Virtual Machine, providing cryptographic
//! guarantees of isolation between tabs.

mod ui;

use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use citadel_zkvm::{ZkVm, Channel, ChannelMessage};

// Re-export UI components
pub use ui::{TabBar, Message as TabMessage};

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

/// Manages all browser tabs
pub struct TabManager {
    /// All active tabs
    tabs: Arc<RwLock<Vec<Tab>>>,
    /// Currently active tab ID
    active_tab: Arc<RwLock<Option<Uuid>>>,
}

impl Tab {
    /// Create a new tab
    pub async fn new(url: String, tab_type: TabType) -> TabResult<Self> {
        // Create a new ZKVM instance for this tab
        let (vm, channel) = ZkVm::new().await?;
        
        let state = TabState {
            id: Uuid::new_v4(),
            title: String::new(),
            url,
            tab_type,
            is_active: false,
            created_at: chrono::Utc::now(),
        };
        
        let tab = Self {
            state: Arc::new(RwLock::new(state)),
            vm: Arc::new(vm),
            channel,
        };
        
        // Start the VM
        tab.vm.start().await?;
        
        Ok(tab)
    }
    
    /// Convert tab type (with user warning)
    pub async fn convert_to_container(&self) -> TabResult<()> {
        let mut state = self.state.write();
        
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
                    }),
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
        let mut state = self.state.write();
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
        let state = self.state.read();
        if let TabType::Container { container_id } = state.tab_type {
            self.persist_container_state(container_id).await?;
        }
        
        Ok(())
    }
    
    /// Persist container state
    async fn persist_container_state(&self, container_id: Uuid) -> TabResult<()> {
        // TODO: Implement container state persistence
        Ok(())
    }
}

impl TabManager {
    /// Create a new tab manager
    pub fn new() -> Self {
        Self {
            tabs: Arc::new(RwLock::new(Vec::new())),
            active_tab: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Open a new tab
    pub async fn open_tab(&self, url: String, tab_type: TabType) -> TabResult<Uuid> {
        let tab = Tab::new(url, tab_type).await?;
        let tab_id = tab.state.read().id;
        
        let mut tabs = self.tabs.write();
        tabs.push(tab);
        
        // If this is the first tab, make it active
        if tabs.len() == 1 {
            *self.active_tab.write() = Some(tab_id);
        }
        
        Ok(tab_id)
    }
    
    /// Close a tab
    pub async fn close_tab(&self, tab_id: Uuid) -> TabResult<()> {
        let mut tabs = self.tabs.write();
        
        // Find and remove the tab
        if let Some(index) = tabs.iter().position(|t| t.state.read().id == tab_id) {
            let tab = tabs.remove(index);
            tab.close().await?;
            
            // Update active tab if necessary
            let mut active_tab = self.active_tab.write();
            if active_tab.map_or(false, |id| id == tab_id) {
                *active_tab = tabs.first().map(|t| t.state.read().id);
            }
        }
        
        Ok(())
    }
    
    /// Switch to a different tab
    pub async fn switch_tab(&self, tab_id: Uuid) -> TabResult<()> {
        let tabs = self.tabs.read();
        
        // Verify tab exists
        if !tabs.iter().any(|t| t.state.read().id == tab_id) {
            return Err(TabError::NotFound(tab_id));
        }
        
        // Update active states
        for tab in tabs.iter() {
            let mut state = tab.state.write();
            state.is_active = state.id == tab_id;
        }
        
        *self.active_tab.write() = Some(tab_id);
        Ok(())
    }
    
    /// Convert a tab to a container
    pub async fn convert_to_container(&self, tab_id: Uuid) -> TabResult<()> {
        let tabs = self.tabs.read();
        
        // Find the tab
        if let Some(tab) = tabs.iter().find(|t| t.state.read().id == tab_id) {
            tab.convert_to_container().await?;
        } else {
            return Err(TabError::NotFound(tab_id));
        }
        
        Ok(())
    }
    
    /// Get all tab states
    pub fn get_tab_states(&self) -> Vec<TabState> {
        let tabs = self.tabs.read();
        tabs.iter()
            .map(|tab| tab.state.read().clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::block_on;
    
    #[test]
    fn test_tab_lifecycle() {
        block_on(async {
            let manager = TabManager::new();
            
            // Open a new ephemeral tab
            let tab_id = manager.open_tab(
                "https://example.com".into(),
                TabType::Ephemeral
            ).await.unwrap();
            
            // Verify tab exists
            let states = manager.get_tab_states();
            assert_eq!(states.len(), 1);
            assert_eq!(states[0].id, tab_id);
            assert_eq!(states[0].url, "https://example.com");
            
            // Close the tab
            manager.close_tab(tab_id).await.unwrap();
            assert_eq!(manager.get_tab_states().len(), 0);
        });
    }
    
    #[test]
    fn test_tab_conversion() {
        block_on(async {
            let manager = TabManager::new();
            
            // Open an ephemeral tab
            let tab_id = manager.open_tab(
                "https://example.com".into(),
                TabType::Ephemeral
            ).await.unwrap();
            
            // Convert to container
            manager.convert_to_container(tab_id).await.unwrap();
            
            // Verify conversion
            let states = manager.get_tab_states();
            match states[0].tab_type {
                TabType::Container { .. } => (),
                _ => panic!("Tab should be a container"),
            }
        });
    }
    
    #[test]
    fn test_tab_switching() {
        block_on(async {
            let manager = TabManager::new();
            
            // Open two tabs
            let tab1 = manager.open_tab(
                "https://example1.com".into(),
                TabType::Ephemeral
            ).await.unwrap();
            
            let tab2 = manager.open_tab(
                "https://example2.com".into(),
                TabType::Ephemeral
            ).await.unwrap();
            
            // Switch to second tab
            manager.switch_tab(tab2).await.unwrap();
            
            // Verify active states
            let states = manager.get_tab_states();
            assert!(!states.iter().find(|s| s.id == tab1).unwrap().is_active);
            assert!(states.iter().find(|s| s.id == tab2).unwrap().is_active);
        });
    }
} 