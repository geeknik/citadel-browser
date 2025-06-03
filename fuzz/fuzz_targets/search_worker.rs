#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use citadel_tabs::search_worker::{SearchWorker, ControlMessage};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use uuid::Uuid;

#[derive(Debug, Arbitrary)]
struct SearchWorkerInput {
    // Fuzz different operations
    operations: Vec<Operation>,
    // Fuzz different search terms
    search_terms: Vec<String>,
    // Fuzz different encryption keys
    encryption_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Arbitrary)]
enum Operation {
    UpdateIndex {
        tab_id: String,
        terms: Vec<String>,
    },
    RemoveTab {
        tab_id: String,
    },
    Search {
        query: String,
    },
}

fuzz_target!(|input: SearchWorkerInput| {
    // Create worker instance
    let mut worker = SearchWorker::new();
    
    // Track active tabs and their keys for validation
    let mut active_tabs = std::collections::HashMap::new();
    
    // Process each operation
    for op in input.operations {
        match op {
            Operation::UpdateIndex { tab_id, terms } => {
                if let Ok(tab_uuid) = Uuid::parse_str(&tab_id) {
                    // Get or generate encryption key
                    let key = if !input.encryption_keys.is_empty() {
                        input.encryption_keys[0].clone()
                    } else {
                        vec![0u8; 32]
                    };
                    
                    // Encrypt terms
                    let encrypted_terms: Vec<Vec<u8>> = terms.iter()
                        .filter_map(|term| {
                            if let Ok(cipher) = Aes256Gcm::new_from_slice(&key) {
                                let nonce = Nonce::from_slice(&[0u8; 12]);
                                cipher.encrypt(nonce, term.as_bytes()).ok()
                            } else {
                                None
                            }
                        })
                        .collect();
                    
                    // Update index
                    let _ = worker.handle_message(ControlMessage::UpdateIndex {
                        tab_id: tab_uuid.to_string(),
                        terms: encrypted_terms,
                        key: key.clone(),
                    });
                    
                    // Track active tab
                    active_tabs.insert(tab_uuid, (terms, key));
                }
            },
            Operation::RemoveTab { tab_id } => {
                if let Ok(tab_uuid) = Uuid::parse_str(&tab_id) {
                    let _ = worker.handle_message(ControlMessage::RemoveTab {
                        tab_id: tab_uuid.to_string(),
                    });
                    active_tabs.remove(&tab_uuid);
                }
            },
            Operation::Search { query } => {
                // Try searching with each active tab's key
                for (tab_id, (_, key)) in &active_tabs {
                    if let Ok(cipher) = Aes256Gcm::new_from_slice(key) {
                        let nonce = Nonce::from_slice(&[0u8; 12]);
                        if let Ok(encrypted_query) = cipher.encrypt(nonce, query.as_bytes()) {
                            let _ = worker.search(&encrypted_query, key);
                        }
                    }
                }
            }
        }
    }
    
    // Verify no panics occurred during operations
}); 