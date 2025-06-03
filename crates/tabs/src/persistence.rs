use std::{path::PathBuf, sync::Arc};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use blake3::Hash;
use crate::{TabError, TabResult, TabState};

/// Encrypted container state
#[derive(Serialize, Deserialize)]
struct ContainerState {
    /// Container identifier
    id: Uuid,
    /// Encrypted tab state
    encrypted_state: Vec<u8>,
    /// State verification hash
    state_hash: Hash,
    /// Encryption nonce
    nonce: [u8; 12],
}

/// Manages persistent container storage
pub struct ContainerStore {
    /// Root storage directory
    storage_dir: PathBuf,
    /// Encryption keys by container ID
    keys: Arc<RwLock<HashMap<Uuid, [u8; 32]>>>,
}

impl ContainerStore {
    /// Create a new container store
    pub fn new(storage_dir: PathBuf) -> TabResult<Self> {
        // Ensure storage directory exists
        std::fs::create_dir_all(&storage_dir)
            .map_err(|e| TabError::PersistenceError(format!("Failed to create storage dir: {}", e)))?;
            
        Ok(Self {
            storage_dir,
            keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Generate a new encryption key for a container
    pub fn create_container(&self, container_id: Uuid) -> TabResult<()> {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        
        let mut keys = self.keys.write();
        keys.insert(container_id, key);
        
        Ok(())
    }
    
    /// Save container state
    pub async fn save_state(&self, container_id: Uuid, state: &TabState) -> TabResult<()> {
        // Get container key
        let keys = self.keys.read();
        let key = keys.get(&container_id)
            .ok_or_else(|| TabError::PersistenceError("Container key not found".into()))?;
            
        // Serialize state
        let state_bytes = bincode::serialize(state)
            .map_err(|e| TabError::PersistenceError(format!("Serialization failed: {}", e)))?;
            
        // Generate nonce
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        
        // Encrypt state
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| TabError::PersistenceError(format!("Encryption failed: {}", e)))?;
            
        let encrypted_state = cipher
            .encrypt(Nonce::from_slice(&nonce), state_bytes.as_ref())
            .map_err(|e| TabError::PersistenceError(format!("Encryption failed: {}", e)))?;
            
        // Calculate state hash
        let state_hash = blake3::hash(&state_bytes);
        
        // Create container state
        let container_state = ContainerState {
            id: container_id,
            encrypted_state,
            state_hash,
            nonce,
        };
        
        // Save to file
        let path = self.storage_dir.join(format!("{}.state", container_id));
        tokio::fs::write(&path, bincode::serialize(&container_state)?)
            .await
            .map_err(|e| TabError::PersistenceError(format!("Failed to write state: {}", e)))?;
            
        Ok(())
    }
    
    /// Load container state
    pub async fn load_state(&self, container_id: Uuid) -> TabResult<TabState> {
        // Get container key
        let keys = self.keys.read();
        let key = keys.get(&container_id)
            .ok_or_else(|| TabError::PersistenceError("Container key not found".into()))?;
            
        // Read state file
        let path = self.storage_dir.join(format!("{}.state", container_id));
        let container_state: ContainerState = bincode::deserialize(
            &tokio::fs::read(&path)
                .await
                .map_err(|e| TabError::PersistenceError(format!("Failed to read state: {}", e)))?
        )?;
        
        // Verify container ID
        if container_state.id != container_id {
            return Err(TabError::PersistenceError("Container ID mismatch".into()));
        }
        
        // Decrypt state
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| TabError::PersistenceError(format!("Decryption failed: {}", e)))?;
            
        let state_bytes = cipher
            .decrypt(
                Nonce::from_slice(&container_state.nonce),
                container_state.encrypted_state.as_ref()
            )
            .map_err(|e| TabError::PersistenceError(format!("Decryption failed: {}", e)))?;
            
        // Verify state hash
        let calculated_hash = blake3::hash(&state_bytes);
        if calculated_hash != container_state.state_hash {
            return Err(TabError::PersistenceError("State hash mismatch".into()));
        }
        
        // Deserialize state
        let state: TabState = bincode::deserialize(&state_bytes)
            .map_err(|e| TabError::PersistenceError(format!("Deserialization failed: {}", e)))?;
            
        Ok(state)
    }
    
    /// Delete container state
    pub async fn delete_state(&self, container_id: Uuid) -> TabResult<()> {
        // Remove encryption key
        let mut keys = self.keys.write();
        keys.remove(&container_id);
        
        // Delete state file
        let path = self.storage_dir.join(format!("{}.state", container_id));
        if path.exists() {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| TabError::PersistenceError(format!("Failed to delete state: {}", e)))?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio_test::block_on;
    
    #[test]
    fn test_container_persistence() {
        block_on(async {
            let temp_dir = tempdir().unwrap();
            let store = ContainerStore::new(temp_dir.path().to_path_buf()).unwrap();
            
            // Create container
            let container_id = Uuid::new_v4();
            store.create_container(container_id).unwrap();
            
            // Create test state
            let state = TabState {
                id: Uuid::new_v4(),
                title: "Test Tab".into(),
                url: "https://example.com".into(),
                tab_type: crate::TabType::Container { container_id },
                is_active: true,
                created_at: chrono::Utc::now(),
            };
            
            // Save state
            store.save_state(container_id, &state).await.unwrap();
            
            // Load state
            let loaded_state = store.load_state(container_id).await.unwrap();
            
            // Verify state
            assert_eq!(state.id, loaded_state.id);
            assert_eq!(state.title, loaded_state.title);
            assert_eq!(state.url, loaded_state.url);
            
            // Delete state
            store.delete_state(container_id).await.unwrap();
            assert!(store.load_state(container_id).await.is_err());
        });
    }
} 