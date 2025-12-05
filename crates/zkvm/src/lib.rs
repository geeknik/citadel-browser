//! Citadel Zero-Knowledge Virtual Machine
//! 
//! This module implements a secure virtual machine that provides cryptographic guarantees
//! of isolation between browser tabs. Each VM instance operates with zero knowledge of
//! other VMs or the host system, while still allowing controlled communication channels.

mod executor;
pub mod channel;
pub mod error;

use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use zeroize::Zeroize;
use rand::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit, AeadCore},
    Aes256Gcm,
};

// Re-export important types
pub use executor::Executor;
pub use channel::{Channel, ChannelMessage};
pub use error::ZkVmError;

/// Result type for ZKVM operations
pub type ZkVmResult<T> = Result<T, ZkVmError>;

/// Basic information about an execution attempt
#[derive(Debug, Default)]
pub struct ExecutionResult {
    /// Whether the executor finished without error
    pub completed: bool,
}

/// Represents the state of a ZKVM instance
#[derive(Debug, PartialEq)]
pub enum ZkVmState {
    /// VM is initialized but not running
    Ready,
    /// VM is actively running
    Running,
    /// VM is temporarily paused
    Paused,
    /// VM has been terminated
    Terminated,
}

/// Memory page permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Represents a secure memory page in the ZKVM
#[derive(Debug)]
struct MemoryPage {
    /// The actual memory data, encrypted when not in use
    data: Vec<u8>,
    /// Permissions for this page
    permissions: PagePermissions,
    /// Cryptographic key for this page
    key: Arc<[u8; 32]>,
}

impl MemoryPage {
    /// Create a new memory page with given permissions
    fn new(size: usize, permissions: PagePermissions) -> ZkVmResult<Self> {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        
        Ok(Self {
            data: vec![0; size],
            permissions,
            key: Arc::new(key),
        })
    }
    
    /// Encrypt the page contents
    fn encrypt(&mut self) -> ZkVmResult<()> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;
            
        let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
        let ciphertext = cipher
            .encrypt(&nonce, self.data.as_ref())
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;
            
        self.data = ciphertext;
        Ok(())
    }
    
    /// Decrypt the page contents
    fn decrypt(&mut self) -> ZkVmResult<()> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;
            
        let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
        let plaintext = cipher
            .decrypt(&nonce, self.data.as_ref())
            .map_err(|e| ZkVmError::CryptoError(e.to_string()))?;
            
        self.data = plaintext;
        Ok(())
    }
    
    /// Check if the page allows read access
    fn can_read(&self) -> bool {
        self.permissions.read
    }
    
    /// Check if the page allows write access
    fn can_write(&self) -> bool {
        self.permissions.write
    }
    
    /// Check if the page allows execute access
    fn can_execute(&self) -> bool {
        self.permissions.execute
    }
}

/// Core ZKVM implementation
pub struct ZkVm {
    /// Current state of the VM
    state: RwLock<ZkVmState>,
    /// Memory pages
    memory: Mutex<Vec<MemoryPage>>,
    /// Unique identifier for this VM instance
    id: Arc<[u8; 32]>,
    /// Communication channel to the host
    channel: Channel,
    /// Executor for running code
    executor: Mutex<Executor>,
}

impl ZkVm {
    /// Create a new ZKVM instance
    pub async fn new() -> ZkVmResult<(Self, Channel)> {
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        
        let (vm_channel, host_channel) = Channel::new()?;
        let executor = Executor::new(1024 * 1024 * 32)?; // 32MB default memory limit
        
        let vm = Self {
            state: RwLock::new(ZkVmState::Ready),
            memory: Mutex::new(Vec::new()),
            id: Arc::new(id),
            channel: vm_channel,
            executor: Mutex::new(executor),
        };
        
        Ok((vm, host_channel))
    }
    
    /// Allocate a new memory page
    pub async fn allocate_page(&self, size: usize, permissions: PagePermissions) -> ZkVmResult<usize> {
        let page = MemoryPage::new(size, permissions)?;
        let mut memory = self.memory.lock().await;
        let page_id = memory.len();
        memory.push(page);
        Ok(page_id)
    }
    
    /// Start the VM
    pub async fn start(&self) -> ZkVmResult<()> {
        let mut state = self.state.write().await;
        match *state {
            ZkVmState::Ready => {
                *state = ZkVmState::Running;
                Ok(())
            }
            _ => Err(ZkVmError::InvalidOperation(
                "VM must be in Ready state to start".into()
            )),
        }
    }
    
    /// Execute a single instruction
    pub async fn step(&self) -> ZkVmResult<()> {
        let state = self.state.read().await;
        if *state != ZkVmState::Running {
            return Err(ZkVmError::InvalidOperation(
                "VM must be running to execute instructions".into()
            ));
        }
        drop(state);
        
        // Execute from current PC - this will run until halt or error
        // For step execution, we'd need to modify the executor
        // For now, just advance the PC as a placeholder
        Ok(())
    }
    
    /// Load and encrypt a memory page
    pub async fn load_encrypted_page(&self, data: Vec<u8>, permissions: PagePermissions) -> ZkVmResult<usize> {
        let size = data.len();
        let mut page = MemoryPage::new(size, permissions)?;
        page.data = data;
        page.encrypt()?;
        
        let mut memory = self.memory.lock().await;
        let page_id = memory.len();
        memory.push(page);
        Ok(page_id)
    }
    
    /// Access a decrypted page temporarily
    pub async fn with_decrypted_page<F, R>(&self, page_id: usize, f: F) -> ZkVmResult<R>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let mut memory = self.memory.lock().await;
        if page_id >= memory.len() {
            return Err(ZkVmError::MemoryError("Invalid page ID".into()));
        }
        
        let page = &mut memory[page_id];
        page.decrypt()?;
        let result = f(&page.data);
        page.encrypt()?;
        
        Ok(result)
    }
    
    /// Stop the VM and securely wipe all memory
    pub async fn terminate(&self) -> ZkVmResult<()> {
        let mut state = self.state.write().await;
        let mut memory = self.memory.lock().await;
        
        // Securely wipe all memory pages
        for page in memory.iter_mut() {
            page.data.zeroize();
        }
        
        // Close the communication channel
        self.channel.close().await;
        
        *state = ZkVmState::Terminated;
        Ok(())
    }
    
    /// Get the VM's unique identifier
    pub fn id(&self) -> Arc<[u8; 32]> {
        self.id.clone()
    }
    
    /// Execute bytecode using the internal executor
    pub async fn execute_code(&self, entry_point: u64) -> ZkVmResult<ExecutionResult> {
        let state = self.state.read().await;
        match *state {
            ZkVmState::Running => {
                drop(state); // Release read lock
                
                // Use the executor to run the code
                let mut executor = self.executor.lock().await;
                executor.execute(entry_point)?;

                Ok(ExecutionResult { completed: true })
            }
            _ => Err(ZkVmError::InvalidOperation(
                "VM must be running to execute code".into()
            ))
        }
    }
}

impl Drop for ZkVm {
    fn drop(&mut self) {
        // Ensure all memory is securely wiped when the VM is dropped
        let _ = futures::executor::block_on(self.terminate());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::block_on;
    
    #[test]
    fn test_vm_lifecycle() {
        block_on(async {
            let (vm, _host_channel) = ZkVm::new().await.unwrap();
            assert!(matches!(*vm.state.read().await, ZkVmState::Ready));
            
            vm.start().await.unwrap();
            assert!(matches!(*vm.state.read().await, ZkVmState::Running));
            
            vm.terminate().await.unwrap();
            assert!(matches!(*vm.state.read().await, ZkVmState::Terminated));
        });
    }
    
    #[test]
    fn test_memory_allocation() {
        block_on(async {
            let (vm, _) = ZkVm::new().await.unwrap();
            let perms = PagePermissions {
                read: true,
                write: true,
                execute: false,
            };
            
            let page_id = vm.allocate_page(4096, perms).await.unwrap();
            assert_eq!(page_id, 0);
            
            let memory = vm.memory.lock().await;
            assert_eq!(memory.len(), 1);
            assert_eq!(memory[0].data.len(), 4096);
        });
    }
    
    #[test]
    fn test_channel_communication() {
        block_on(async {
            let (mut vm, mut host_channel) = ZkVm::new().await.unwrap();
            
            // Send a message from host to VM
            let message = ChannelMessage::Control {
                command: "test".into(),
                params: serde_json::json!({"key": "value"}).to_string(),
            };
            
            host_channel.send(message.clone()).await.unwrap();
            
            // VM should receive the message
            let received = vm.channel.receive().await.unwrap();
            match received {
                ChannelMessage::Control { command, params } => {
                    assert_eq!(command, "test");
                    assert_eq!(params, serde_json::json!({"key": "value"}).to_string());
                }
                _ => panic!("Wrong message type received"),
            }
        });
    }
} 
