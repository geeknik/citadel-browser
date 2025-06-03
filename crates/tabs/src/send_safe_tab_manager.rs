//! Send-safe wrapper for ZKVM TabManager
//! 
//! This module provides a Send-safe interface to the ZKVM TabManager
//! by using message passing and async operations.

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, oneshot};
use uuid::Uuid;
use crate::{TabError, TabResult, TabType, TabState, PageContent};

/// Commands that can be sent to the tab manager
#[derive(Debug)]
pub enum TabManagerCommand {
    OpenTab {
        url: String,
        tab_type: TabType,
        response: oneshot::Sender<TabResult<Uuid>>,
    },
    CloseTab {
        tab_id: Uuid,
        response: oneshot::Sender<TabResult<()>>,
    },
    SwitchTab {
        tab_id: Uuid,
        response: oneshot::Sender<TabResult<()>>,
    },
    GetTabStates {
        response: oneshot::Sender<Vec<TabState>>,
    },
    ConvertToContainer {
        tab_id: Uuid,
        response: oneshot::Sender<TabResult<()>>,
    },
    UpdatePageContent {
        tab_id: Uuid,
        content: PageContent,
        response: oneshot::Sender<TabResult<()>>,
    },
}

/// Send-safe wrapper for TabManager
#[derive(Clone)]
pub struct SendSafeTabManager {
    command_sender: mpsc::UnboundedSender<TabManagerCommand>,
    tab_states: Arc<RwLock<Vec<TabState>>>,
}

impl SendSafeTabManager {
    /// Create a new Send-safe tab manager
    pub fn new() -> Self {
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let tab_states = Arc::new(RwLock::new(Vec::new()));
        
        // Spawn the background task that handles tab management
        let manager_states = tab_states.clone();
        tokio::spawn(async move {
            Self::handle_commands(command_receiver, manager_states).await;
        });
        
        Self {
            command_sender,
            tab_states,
        }
    }
    
    /// Handle commands in the background
    async fn handle_commands(
        mut receiver: mpsc::UnboundedReceiver<TabManagerCommand>,
        states: Arc<RwLock<Vec<TabState>>>,
    ) {
        // For now, we'll simulate tab operations
        // In a real implementation, this would interface with the actual ZKVM TabManager
        while let Some(command) = receiver.recv().await {
            match command {
                TabManagerCommand::OpenTab { url, tab_type, response } => {
                    let tab_id = Uuid::new_v4();
                    let tab_state = TabState {
                        id: tab_id,
                        title: "New Tab".to_string(),
                        url: url.clone(),
                        tab_type,
                        is_active: false,
                        created_at: chrono::Utc::now(),
                        content: PageContent::Loading { url },
                    };
                    
                    let mut states_guard = states.write().await;
                    
                    // If this is the first tab, make it active
                    if states_guard.is_empty() {
                        let mut active_state = tab_state;
                        active_state.is_active = true;
                        states_guard.push(active_state);
                    } else {
                        states_guard.push(tab_state);
                    }
                    
                    let _ = response.send(Ok(tab_id));
                }
                TabManagerCommand::CloseTab { tab_id, response } => {
                    let mut states_guard = states.write().await;
                    
                    if let Some(index) = states_guard.iter().position(|t| t.id == tab_id) {
                        let was_active = states_guard[index].is_active;
                        states_guard.remove(index);
                        
                        // If we closed the active tab, make the first remaining tab active
                        if was_active && !states_guard.is_empty() {
                            states_guard[0].is_active = true;
                        }
                        
                        let _ = response.send(Ok(()));
                    } else {
                        let _ = response.send(Err(TabError::NotFound(tab_id)));
                    }
                }
                TabManagerCommand::SwitchTab { tab_id, response } => {
                    let mut states_guard = states.write().await;
                    
                    // Check if tab exists
                    if !states_guard.iter().any(|t| t.id == tab_id) {
                        let _ = response.send(Err(TabError::NotFound(tab_id)));
                        continue;
                    }
                    
                    // Update active states
                    for state in states_guard.iter_mut() {
                        state.is_active = state.id == tab_id;
                    }
                    
                    let _ = response.send(Ok(()));
                }
                TabManagerCommand::GetTabStates { response } => {
                    let states_guard = states.read().await;
                    let _ = response.send(states_guard.clone());
                }
                TabManagerCommand::ConvertToContainer { tab_id, response } => {
                    let mut states_guard = states.write().await;
                    
                    if let Some(state) = states_guard.iter_mut().find(|t| t.id == tab_id) {
                        match state.tab_type {
                            TabType::Ephemeral => {
                                state.tab_type = TabType::Container {
                                    container_id: Uuid::new_v4(),
                                };
                                let _ = response.send(Ok(()));
                            }
                            TabType::Container { .. } => {
                                let _ = response.send(Err(TabError::InvalidOperation(
                                    "Tab is already a container".into()
                                )));
                            }
                        }
                    } else {
                        let _ = response.send(Err(TabError::NotFound(tab_id)));
                    }
                }
                TabManagerCommand::UpdatePageContent { tab_id, content, response } => {
                    let mut states_guard = states.write().await;
                    
                    if let Some(state) = states_guard.iter_mut().find(|t| t.id == tab_id) {
                        // Update page content
                        state.content = content.clone();
                        
                        // Update tab title if we have loaded content
                        if let PageContent::Loaded { title, .. } = &content {
                            state.title = title.clone();
                        }
                        
                        let _ = response.send(Ok(()));
                    } else {
                        let _ = response.send(Err(TabError::NotFound(tab_id)));
                    }
                }
            }
        }
    }
    
    /// Open a new tab
    pub async fn open_tab(&self, url: String, tab_type: TabType) -> TabResult<Uuid> {
        let (response_sender, response_receiver) = oneshot::channel();
        
        let command = TabManagerCommand::OpenTab {
            url,
            tab_type,
            response: response_sender,
        };
        
        self.command_sender.send(command)
            .map_err(|_| TabError::InvalidOperation("TabManager channel closed".into()))?;
        
        response_receiver.await
            .map_err(|_| TabError::InvalidOperation("Response channel closed".into()))?
    }
    
    /// Close a tab
    pub async fn close_tab(&self, tab_id: Uuid) -> TabResult<()> {
        let (response_sender, response_receiver) = oneshot::channel();
        
        let command = TabManagerCommand::CloseTab {
            tab_id,
            response: response_sender,
        };
        
        self.command_sender.send(command)
            .map_err(|_| TabError::InvalidOperation("TabManager channel closed".into()))?;
        
        response_receiver.await
            .map_err(|_| TabError::InvalidOperation("Response channel closed".into()))?
    }
    
    /// Switch to a different tab
    pub async fn switch_tab(&self, tab_id: Uuid) -> TabResult<()> {
        let (response_sender, response_receiver) = oneshot::channel();
        
        let command = TabManagerCommand::SwitchTab {
            tab_id,
            response: response_sender,
        };
        
        self.command_sender.send(command)
            .map_err(|_| TabError::InvalidOperation("TabManager channel closed".into()))?;
        
        response_receiver.await
            .map_err(|_| TabError::InvalidOperation("Response channel closed".into()))?
    }
    
    /// Get all tab states
    pub fn get_tab_states(&self) -> Vec<TabState> {
        // For immediate access, return the cached states
        // This is safe because we only read the data
        match self.tab_states.try_read() {
            Ok(states) => states.clone(),
            Err(_) => Vec::new(), // Return empty if locked
        }
    }
    
    /// Convert a tab to a container
    pub async fn convert_to_container(&self, tab_id: Uuid) -> TabResult<()> {
        let (response_sender, response_receiver) = oneshot::channel();
        
        let command = TabManagerCommand::ConvertToContainer {
            tab_id,
            response: response_sender,
        };
        
        self.command_sender.send(command)
            .map_err(|_| TabError::InvalidOperation("TabManager channel closed".into()))?;
        
        response_receiver.await
            .map_err(|_| TabError::InvalidOperation("Response channel closed".into()))?
    }
    
    /// Update page content for a tab
    pub async fn update_page_content(&self, tab_id: Uuid, content: PageContent) -> TabResult<()> {
        let (response_sender, response_receiver) = oneshot::channel();
        
        let command = TabManagerCommand::UpdatePageContent {
            tab_id,
            content,
            response: response_sender,
        };
        
        self.command_sender.send(command)
            .map_err(|_| TabError::InvalidOperation("TabManager channel closed".into()))?;
        
        response_receiver.await
            .map_err(|_| TabError::InvalidOperation("Response channel closed".into()))?
    }
}

// Implement Send and Sync for the wrapper
unsafe impl Send for SendSafeTabManager {}
unsafe impl Sync for SendSafeTabManager {} 