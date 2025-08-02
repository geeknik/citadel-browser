use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use blake3::Hash;
use crate::{ZkVmResult, ZkVmError};
use rand::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use serde::{Serialize, Deserialize};

/// Message types that can be sent through the channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelMessage {
    /// Request to load a resource
    ResourceRequest {
        url: String,
        headers: Vec<(String, String)>,
    },
    /// Resource response
    ResourceResponse {
        data: Vec<u8>,
        content_type: String,
    },
    /// UI event
    UiEvent {
        event_type: String,
        data: String, // JSON string to avoid bincode issues
    },
    /// Control message
    Control {
        command: String,
        params: String, // JSON string to avoid bincode issues
    },
}

/// A secure, one-way communication channel
pub struct Channel {
    /// Sender end of the channel
    sender: mpsc::Sender<EncryptedMessage>,
    /// Receiver end of the channel
    receiver: mpsc::Receiver<EncryptedMessage>,
    /// Channel encryption key
    key: Arc<[u8; 32]>,
    /// Channel state
    state: Arc<RwLock<ChannelState>>,
}

/// Represents an encrypted message in transit
#[derive(Debug)]
struct EncryptedMessage {
    /// Encrypted message content
    content: Vec<u8>,
    /// Message authentication code
    mac: Hash,
    /// Nonce used for encryption
    nonce: [u8; 12],
}

/// Channel state information
#[derive(Debug)]
struct ChannelState {
    /// Number of messages sent
    messages_sent: u64,
    /// Number of messages received
    messages_received: u64,
    /// Whether the channel is active
    active: bool,
}

/// Represents a secure communication channel
#[derive(Debug)]
pub struct SecureChannel {
    /// Encryption key
    key: [u8; 32],
}

impl SecureChannel {
    /// Create a new secure channel with the given key
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypt a message
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ZkVmError> {
        // Create a new nonce for this encryption
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let nonce = aes_gcm::Nonce::from_slice(&nonce);

        // Create cipher instance
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;

        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a message
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ZkVmError> {
        // Extract nonce from ciphertext
        if ciphertext.len() < 12 {
            return Err(ZkVmError::CryptoError("Invalid ciphertext length".into()));
        }
        let nonce = aes_gcm::Nonce::from_slice(&ciphertext[..12]);
        let encrypted_data = &ciphertext[12..];

        // Create cipher instance
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;

        // Decrypt the ciphertext
        cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))
    }
}

impl Channel {
    /// Create a new secure channel pair
    pub fn new() -> ZkVmResult<(Self, Self)> {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let key = Arc::new(key);
        
        let (tx1, rx1) = mpsc::channel(32);
        let (tx2, rx2) = mpsc::channel(32);
        
        let channel1 = Self {
            sender: tx1,
            receiver: rx2,
            key: key.clone(),
            state: Arc::new(RwLock::new(ChannelState {
                messages_sent: 0,
                messages_received: 0,
                active: true,
            })),
        };
        
        let channel2 = Self {
            sender: tx2,
            receiver: rx1,
            key: key.clone(),
            state: Arc::new(RwLock::new(ChannelState {
                messages_sent: 0,
                messages_received: 0,
                active: true,
            })),
        };
        
        Ok((channel1, channel2))
    }
    
    /// Send a message through the channel
    pub async fn send(&self, message: ChannelMessage) -> ZkVmResult<()> {
        let mut state = self.state.write().await;
        if !state.active {
            return Err(ZkVmError::ChannelError("Channel is closed".into()));
        }
        
        // Serialize the message
        let message_bytes = bincode::serialize(&message)
            .map_err(|e| ZkVmError::ChannelError(format!("Serialization failed: {}", e)))?;
        
        // Generate nonce
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        
        // Encrypt the message
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;
            
        let encrypted = cipher
            .encrypt(aes_gcm::Nonce::from_slice(&nonce), message_bytes.as_ref())
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;
        
        // Calculate MAC
        let mac = blake3::hash(&encrypted);
        
        // Create encrypted message
        let encrypted_message = EncryptedMessage {
            content: encrypted,
            mac,
            nonce,
        };
        
        // Send the message
        self.sender
            .send(encrypted_message)
            .await
            .map_err(|e| ZkVmError::ChannelError(format!("Send failed: {}", e)))?;
        
        state.messages_sent += 1;
        Ok(())
    }
    
    /// Receive a message from the channel
    pub async fn receive(&mut self) -> ZkVmResult<ChannelMessage> {
        let mut state = self.state.write().await;
        if !state.active {
            return Err(ZkVmError::ChannelError("Channel is closed".into()));
        }
        
        // Receive encrypted message
        let encrypted_message = self.receiver
            .recv()
            .await
            .ok_or_else(|| ZkVmError::ChannelError("Channel closed".into()))?;
        
        // Verify MAC
        let calculated_mac = blake3::hash(&encrypted_message.content);
        if calculated_mac != encrypted_message.mac {
            return Err(ZkVmError::ChannelError("Message authentication failed".into()));
        }
        
        // Decrypt the message
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;
            
        let decrypted = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&encrypted_message.nonce),
                encrypted_message.content.as_ref()
            )
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;
        
        // Deserialize the message
        let message = bincode::deserialize(&decrypted)
            .map_err(|e| ZkVmError::ChannelError(format!("Deserialization failed: {}", e)))?;
        
        state.messages_received += 1;
        Ok(message)
    }
    
    /// Close the channel
    pub async fn close(&self) {
        let mut state = self.state.write().await;
        state.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::block_on;
    
    #[test]
    fn test_channel_creation() {
        block_on(async {
            let (channel1, channel2) = Channel::new().unwrap();
            assert!(channel1.state.read().await.active);
            assert!(channel2.state.read().await.active);
        });
    }
    
    #[test]
    fn test_message_transmission() {
        let (mut channel1, mut channel2) = Channel::new().unwrap();
        
        // Send a test message
        let message = ChannelMessage::Control {
            command: "test".into(),
            params: serde_json::json!({"key": "value"}).to_string(),
        };
        
        block_on(async {
            channel1.send(message.clone()).await.unwrap();
            let received = channel2.receive().await.unwrap();
            
            match (message, received) {
                (
                    ChannelMessage::Control { command: c1, params: p1 },
                    ChannelMessage::Control { command: c2, params: p2 }
                ) => {
                    assert_eq!(c1, c2);
                    assert_eq!(p1, p2);
                }
                _ => panic!("Message type mismatch"),
            }
        });
    }
    
    #[test]
    fn test_channel_closure() {
        block_on(async {
            let (channel1, _) = Channel::new().unwrap();
            channel1.close().await;
            assert!(!channel1.state.read().await.active);
        });
    }

    #[test]
    fn test_encryption_decryption() {
        let key = [42u8; 32];
        let channel = SecureChannel::new(key);
        
        let message = b"Hello, World!";
        let encrypted = channel.encrypt(message).unwrap();
        let decrypted = channel.decrypt(&encrypted).unwrap();
        
        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_encryption_different_messages() {
        let key = [42u8; 32];
        let channel = SecureChannel::new(key);
        
        let message1 = b"Hello";
        let message2 = b"World";
        
        let encrypted1 = channel.encrypt(message1).unwrap();
        let encrypted2 = channel.encrypt(message2).unwrap();
        
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_decryption_failure() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        
        let channel1 = SecureChannel::new(key1);
        let channel2 = SecureChannel::new(key2);
        
        let message = b"Secret message";
        let encrypted = channel1.encrypt(message).unwrap();
        
        // Trying to decrypt with wrong key should fail
        assert!(channel2.decrypt(&encrypted).is_err());
    }
} 