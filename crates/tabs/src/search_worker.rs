use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use citadel_zkvm::{Worker, ChannelMessage};
use uuid::Uuid;

/// Search worker that runs in ZKVM isolation
pub struct SearchWorker {
    /// Encrypted search index
    index: HashMap<Uuid, Vec<u8>>,
    /// Encryption keys for each tab
    keys: HashMap<Uuid, Vec<u8>>,
}

impl Worker for SearchWorker {
    fn new() -> Self {
        Self {
            index: HashMap::new(),
            keys: HashMap::new(),
        }
    }
    
    async fn handle_message(&mut self, msg: ChannelMessage) -> Result<Option<ChannelMessage>, Box<dyn std::error::Error>> {
        match msg {
            ChannelMessage::Control { command, params } => {
                match command.as_str() {
                    "update_index" => {
                        self.handle_update_index(params).await?;
                        Ok(None)
                    }
                    "remove_tab" => {
                        self.handle_remove_tab(params).await?;
                        Ok(None)
                    }
                    "search" => {
                        let results = self.handle_search(params).await?;
                        Ok(Some(ChannelMessage::Control {
                            command: "search_results".into(),
                            params: serde_json::to_value(results)?,
                        }))
                    }
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }
}

impl SearchWorker {
    /// Handle index update message
    async fn handle_update_index(&mut self, params: Value) -> Result<(), Box<dyn std::error::Error>> {
        let tab_id = Uuid::parse_str(params["tab_id"].as_str().unwrap())?;
        let key = params["key"].as_array().unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect::<Vec<_>>();
            
        // Store encryption key
        self.keys.insert(tab_id, key);
        
        Ok(())
    }
    
    /// Handle tab removal message
    async fn handle_remove_tab(&mut self, params: Value) -> Result<(), Box<dyn std::error::Error>> {
        let tab_id = Uuid::parse_str(params["tab_id"].as_str().unwrap())?;
        
        // Remove tab data
        self.index.remove(&tab_id);
        self.keys.remove(&tab_id);
        
        Ok(())
    }
    
    /// Handle search request
    async fn handle_search(&self, params: Value) -> Result<Vec<SearchResult>, Box<dyn std::error::Error>> {
        let query = params["query"].as_str().unwrap().to_lowercase();
        let mut results = Vec::new();
        
        // Search through encrypted index
        for (tab_id, encrypted_terms) in &self.index {
            if let Some(key) = self.keys.get(tab_id) {
                // Decrypt terms
                let cipher = aes_gcm::Aes256Gcm::new_from_slice(key)?;
                let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
                
                if let Ok(terms) = cipher.decrypt(nonce, encrypted_terms.as_slice()) {
                    let terms = String::from_utf8(terms)?;
                    
                    // Calculate match confidence
                    let confidence = self.calculate_confidence(&terms, &query);
                    
                    if confidence > 0.0 {
                        results.push(SearchResult {
                            tab_id: *tab_id,
                            confidence,
                        });
                    }
                }
            }
        }
        
        // Sort by confidence
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        
        Ok(results)
    }
    
    /// Calculate search match confidence
    fn calculate_confidence(&self, terms: &str, query: &str) -> f32 {
        let terms: Vec<&str> = terms.split_whitespace().collect();
        let query_terms: Vec<&str> = query.split_whitespace().collect();
        
        let mut matches = 0;
        let mut total_terms = query_terms.len();
        
        for query_term in query_terms {
            if terms.iter().any(|term| term.contains(query_term)) {
                matches += 1;
            }
        }
        
        if total_terms == 0 {
            total_terms = 1;
        }
        
        matches as f32 / total_terms as f32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub tab_id: Uuid,
    pub confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use rand::RngCore;
    use uuid::Uuid;

    fn generate_encryption_key() -> Vec<u8> {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    fn encrypt_term(term: &str, key: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = Nonce::from_slice(&[0u8; 12]);
        cipher.encrypt(nonce, term.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn test_search_worker_lifecycle() {
        let mut worker = SearchWorker::new();
        let tab_id = Uuid::new_v4().to_string();
        let key = generate_encryption_key();

        // Test index update
        let terms = vec!["test", "search", "functionality"];
        let encrypted_terms: Vec<Vec<u8>> = terms
            .iter()
            .map(|term| encrypt_term(term, &key))
            .collect();

        let update_msg = ControlMessage::UpdateIndex {
            tab_id: tab_id.clone(),
            terms: encrypted_terms.clone(),
            key: key.clone(),
        };
        worker.handle_message(update_msg).await;

        // Test search
        let search_term = encrypt_term("test", &key);
        let results = worker.search(&search_term, &key).await;
        assert!(results.contains(&tab_id));

        // Test tab removal
        let remove_msg = ControlMessage::RemoveTab {
            tab_id: tab_id.clone(),
        };
        worker.handle_message(remove_msg).await;

        // Verify tab is removed from search results
        let results = worker.search(&search_term, &key).await;
        assert!(!results.contains(&tab_id));
    }

    #[tokio::test]
    async fn test_confidence_calculation() {
        let mut worker = SearchWorker::new();
        let tab_id = Uuid::new_v4().to_string();
        let key = generate_encryption_key();

        // Add test data
        let terms = vec!["citadel", "browser", "privacy"];
        let encrypted_terms: Vec<Vec<u8>> = terms
            .iter()
            .map(|term| encrypt_term(term, &key))
            .collect();

        worker
            .handle_message(ControlMessage::UpdateIndex {
                tab_id: tab_id.clone(),
                terms: encrypted_terms,
                key: key.clone(),
            })
            .await;

        // Test exact match
        let search_term = encrypt_term("citadel", &key);
        let results = worker.search(&search_term, &key).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], tab_id);

        // Test partial match
        let search_term = encrypt_term("cita", &key);
        let results = worker.search(&search_term, &key).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], tab_id);

        // Test no match
        let search_term = encrypt_term("nonexistent", &key);
        let results = worker.search(&search_term, &key).await;
        assert!(results.is_empty());

        // Test empty query
        let search_term = encrypt_term("", &key);
        let results = worker.search(&search_term, &key).await;
        assert!(results.is_empty());
    }
} 