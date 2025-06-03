use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use citadel_zkvm::{ZkVm, Channel, ChannelMessage};
use uuid::Uuid;
use crate::{TabError, TabResult, TabState};

/// Search index entry with encrypted content
#[derive(Serialize, Deserialize)]
struct SearchEntry {
    /// Tab ID
    tab_id: Uuid,
    /// Encrypted search terms
    encrypted_terms: Vec<u8>,
    /// Term verification hash
    terms_hash: blake3::Hash,
}

/// Privacy-preserving tab search engine
pub struct TabSearch {
    /// The ZKVM instance for search operations
    vm: Arc<ZkVm>,
    /// Communication channel to the VM
    channel: Channel,
    /// Search index
    index: Arc<RwLock<Vec<SearchEntry>>>,
}

/// Search result with minimal information exposure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Tab ID that matched
    pub tab_id: Uuid,
    /// Match confidence (0.0 - 1.0)
    pub confidence: f32,
}

impl TabSearch {
    /// Create a new tab search instance
    pub async fn new() -> TabResult<Self> {
        // Create a new ZKVM for search operations
        let (vm, channel) = ZkVm::new().await?;
        
        let search = Self {
            vm: Arc::new(vm),
            channel,
            index: Arc::new(RwLock::new(Vec::new())),
        };
        
        // Start the VM
        search.vm.start().await?;
        
        Ok(search)
    }
    
    /// Index a tab for searching
    pub async fn index_tab(&self, state: &TabState) -> TabResult<()> {
        // Generate search terms from tab state
        let terms = self.generate_search_terms(state);
        
        // Encrypt terms
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key)
            .map_err(|e| TabError::PersistenceError(format!("Encryption failed: {}", e)))?;
            
        let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
        let encrypted_terms = cipher
            .encrypt(nonce, terms.as_bytes())
            .map_err(|e| TabError::PersistenceError(format!("Encryption failed: {}", e)))?;
            
        // Calculate terms hash
        let terms_hash = blake3::hash(terms.as_bytes());
        
        // Create search entry
        let entry = SearchEntry {
            tab_id: state.id,
            encrypted_terms,
            terms_hash,
        };
        
        // Add to index
        let mut index = self.index.write();
        
        // Remove any existing entry for this tab
        index.retain(|e| e.tab_id != state.id);
        
        // Add new entry
        index.push(entry);
        
        // Send index update to search VM
        self.channel.send(ChannelMessage::Control {
            command: "update_index".into(),
            params: serde_json::json!({
                "tab_id": state.id.to_string(),
                "key": key.to_vec(),
            }),
        }).await?;
        
        Ok(())
    }
    
    /// Remove a tab from the search index
    pub async fn remove_tab(&self, tab_id: Uuid) -> TabResult<()> {
        let mut index = self.index.write();
        index.retain(|e| e.tab_id != tab_id);
        
        // Notify search VM
        self.channel.send(ChannelMessage::Control {
            command: "remove_tab".into(),
            params: serde_json::json!({
                "tab_id": tab_id.to_string(),
            }),
        }).await?;
        
        Ok(())
    }
    
    /// Search for tabs matching the query
    pub async fn search(&self, query: &str) -> TabResult<Vec<SearchResult>> {
        // Sanitize query
        let sanitized_query = self.sanitize_query(query);
        
        // Send search request to VM
        self.channel.send(ChannelMessage::Control {
            command: "search".into(),
            params: serde_json::json!({
                "query": sanitized_query,
            }),
        }).await?;
        
        // Receive results
        match self.channel.receive().await? {
            ChannelMessage::Control { command, params } if command == "search_results" => {
                // Deserialize results
                let results: Vec<SearchResult> = serde_json::from_value(params)?;
                Ok(results)
            }
            _ => Err(TabError::InvalidOperation("Invalid search response".into())),
        }
    }
    
    /// Generate search terms from tab state
    fn generate_search_terms(&self, state: &TabState) -> String {
        let mut terms = Vec::new();
        
        // Add title terms
        terms.extend(self.tokenize(&state.title));
        
        // Add URL terms
        terms.extend(self.tokenize(&state.url));
        
        // Join terms
        terms.join(" ")
    }
    
    /// Tokenize text into search terms
    fn tokenize(&self, text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase())
            .collect()
    }
    
    /// Sanitize search query
    fn sanitize_query(&self, query: &str) -> String {
        // Remove any potentially dangerous characters
        query.chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::block_on;
    
    #[test]
    fn test_tab_search() {
        block_on(async {
            let search = TabSearch::new().await.unwrap();
            
            // Create test tabs
            let tab1 = TabState {
                id: Uuid::new_v4(),
                title: "Example Search Page".into(),
                url: "https://example.com/search".into(),
                tab_type: crate::TabType::Ephemeral,
                is_active: true,
                created_at: chrono::Utc::now(),
            };
            
            let tab2 = TabState {
                id: Uuid::new_v4(),
                title: "Another Page".into(),
                url: "https://example.com/other".into(),
                tab_type: crate::TabType::Ephemeral,
                is_active: false,
                created_at: chrono::Utc::now(),
            };
            
            // Index tabs
            search.index_tab(&tab1).await.unwrap();
            search.index_tab(&tab2).await.unwrap();
            
            // Search for "search"
            let results = search.search("search").await.unwrap();
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].tab_id, tab1.id);
            
            // Remove tab and verify it's not found
            search.remove_tab(tab1.id).await.unwrap();
            let results = search.search("search").await.unwrap();
            assert_eq!(results.len(), 0);
        });
    }
    
    #[test]
    fn test_query_sanitization() {
        block_on(async {
            let search = TabSearch::new().await.unwrap();
            
            // Test malicious query sanitization
            let malicious = "SELECT * FROM tabs; DROP TABLE tabs;";
            let sanitized = search.sanitize_query(malicious);
            assert_eq!(sanitized, "SELECT  FROM tabs DROP TABLE tabs");
            
            // Test XSS attempt
            let xss = "<script>alert('xss')</script>";
            let sanitized = search.sanitize_query(xss);
            assert_eq!(sanitized, "scriptalertxssscript");
        });
    }
} 