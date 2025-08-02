//! ZKVM Output Receiver
//!
//! This module handles receiving rendered content from ZKVM-isolated tabs
//! and updating the UI accordingly.

use tokio::sync::mpsc;
use citadel_zkvm::{Channel, ChannelMessage};
use citadel_tabs::zkvm_renderer::RenderedContent;
use uuid::Uuid;

/// Message types for ZKVM output
#[derive(Debug, Clone)]
pub enum ZkVmOutput {
    /// Rendered content ready for display
    RenderedContent {
        tab_id: Uuid,
        content: RenderedContent,
    },
    /// Error from ZKVM
    Error {
        tab_id: Uuid,
        error: String,
    },
}

/// ZKVM output receiver
pub struct ZkVmReceiver {
    /// Channel to send output to the UI
    output_sender: mpsc::UnboundedSender<ZkVmOutput>,
}

impl ZkVmReceiver {
    /// Create a new ZKVM receiver
    pub fn new(output_sender: mpsc::UnboundedSender<ZkVmOutput>) -> Self {
        Self { output_sender }
    }

    /// Start receiving from a ZKVM channel
    pub async fn receive_from_tab(&self, tab_id: Uuid, mut channel: Channel) {
        log::info!("Starting ZKVM receiver for tab {}", tab_id);
        
        loop {
            match channel.receive().await {
                Ok(message) => {
                    if let Err(e) = self.handle_message(tab_id, message).await {
                        log::error!("Error handling ZKVM message from tab {}: {}", tab_id, e);
                    }
                }
                Err(e) => {
                    log::error!("Channel receive error for tab {}: {}", tab_id, e);
                    // Send error to UI
                    let _ = self.output_sender.send(ZkVmOutput::Error {
                        tab_id,
                        error: format!("Channel error: {}", e),
                    });
                    break;
                }
            }
        }
        
        log::info!("ZKVM receiver stopped for tab {}", tab_id);
    }

    /// Handle a message from ZKVM
    async fn handle_message(&self, tab_id: Uuid, message: ChannelMessage) -> Result<(), String> {
        match message {
            ChannelMessage::Control { command, params } => {
                match command.as_str() {
                    "rendered_content" => {
                        // Parse the rendered content from JSON string
                        let content: RenderedContent = serde_json::from_str(&params)
                            .map_err(|e| format!("Failed to parse rendered content: {}", e))?;
                        
                        // Send to UI
                        self.output_sender.send(ZkVmOutput::RenderedContent {
                            tab_id,
                            content,
                        }).map_err(|e| format!("Failed to send output: {}", e))?;
                    }
                    _ => {
                        log::debug!("Unknown control command from ZKVM: {}", command);
                    }
                }
            }
            _ => {
                log::debug!("Unexpected message type from ZKVM");
            }
        }
        
        Ok(())
    }
}

/// Spawn a receiver task for a tab
pub fn spawn_receiver_for_tab(
    tab_id: Uuid,
    channel: Channel,
    output_sender: mpsc::UnboundedSender<ZkVmOutput>,
) {
    let receiver = ZkVmReceiver::new(output_sender);
    
    tokio::spawn(async move {
        receiver.receive_from_tab(tab_id, channel).await;
    });
}