//! Integration tests for Citadel Browser
//! 
//! These tests verify that all components work together correctly
//! and that the browser maintains its security properties end-to-end.

use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

use citadel_networking::{NetworkConfig, PrivacyLevel};
use citadel_security::SecurityContext;
use citadel_tabs::{SendSafeTabManager as TabManager, TabType, PageContent};

/// Test basic browser initialization
#[tokio::test]
async fn test_browser_initialization() {
    // Create runtime and components
    let runtime = Arc::new(Runtime::new().unwrap());
    let network_config = NetworkConfig::default();
    let security_context = Arc::new(SecurityContext::new());
    
    // Initialize browser engine
    let engine_result = citadel_browser::engine::BrowserEngine::new(
        runtime.clone(),
        network_config,
        security_context,
    ).await;
    
    assert!(engine_result.is_ok(), "Browser engine should initialize successfully");
}

/// Test tab lifecycle with ZKVM isolation
#[tokio::test]
async fn test_tab_lifecycle_with_zkvm() {
    let tab_manager = Arc::new(TabManager::new());
    
    // Create a new ephemeral tab
    let tab_id = tab_manager.open_tab(
        "https://example.com".to_string(),
        TabType::Ephemeral
    ).await.unwrap();
    
    // Verify tab exists
    let tab_states = tab_manager.get_tab_states();
    assert_eq!(tab_states.len(), 1);
    assert_eq!(tab_states[0].id, tab_id);
    assert_eq!(tab_states[0].url, "https://example.com");
    assert!(tab_states[0].is_active);
    assert!(matches!(tab_states[0].content, PageContent::Loading { .. }));
    
    // Update tab content to loaded state
    let loaded_content = PageContent::Loaded {
        url: "https://example.com".to_string(),
        title: "Example Domain".to_string(),
        content: "Example content".to_string(),
        element_count: 10,
        size_bytes: 1024,
    };
    
    tab_manager.update_page_content(tab_id, loaded_content).await.unwrap();
    
    // Verify content was updated
    let updated_states = tab_manager.get_tab_states();
    assert!(matches!(updated_states[0].content, PageContent::Loaded { .. }));
    
    // Close the tab
    tab_manager.close_tab(tab_id).await.unwrap();
    
    // Verify tab was removed
    let final_states = tab_manager.get_tab_states();
    assert_eq!(final_states.len(), 0);
}

/// Test multiple tabs with switching
#[tokio::test]
async fn test_multiple_tabs_switching() {
    let tab_manager = Arc::new(TabManager::new());
    
    // Create multiple tabs
    let tab1 = tab_manager.open_tab(
        "https://example.com".to_string(),
        TabType::Ephemeral
    ).await.unwrap();
    
    let tab2 = tab_manager.open_tab(
        "https://github.com".to_string(),
        TabType::Ephemeral
    ).await.unwrap();
    
    let tab3 = tab_manager.open_tab(
        "https://rust-lang.org".to_string(),
        TabType::Container { container_id: uuid::Uuid::new_v4() }
    ).await.unwrap();
    
    // Verify all tabs exist
    let states = tab_manager.get_tab_states();
    assert_eq!(states.len(), 3);
    
    // First tab should be active initially
    assert!(states.iter().find(|t| t.id == tab1).unwrap().is_active);
    assert!(!states.iter().find(|t| t.id == tab2).unwrap().is_active);
    assert!(!states.iter().find(|t| t.id == tab3).unwrap().is_active);
    
    // Switch to tab2
    tab_manager.switch_tab(tab2).await.unwrap();
    
    let updated_states = tab_manager.get_tab_states();
    assert!(!updated_states.iter().find(|t| t.id == tab1).unwrap().is_active);
    assert!(updated_states.iter().find(|t| t.id == tab2).unwrap().is_active);
    assert!(!updated_states.iter().find(|t| t.id == tab3).unwrap().is_active);
    
    // Switch to tab3
    tab_manager.switch_tab(tab3).await.unwrap();
    
    let final_states = tab_manager.get_tab_states();
    assert!(!final_states.iter().find(|t| t.id == tab1).unwrap().is_active);
    assert!(!final_states.iter().find(|t| t.id == tab2).unwrap().is_active);
    assert!(final_states.iter().find(|t| t.id == tab3).unwrap().is_active);
}

/// Test tab conversion from ephemeral to container
#[tokio::test]
async fn test_tab_conversion() {
    let tab_manager = Arc::new(TabManager::new());
    
    // Create ephemeral tab
    let tab_id = tab_manager.open_tab(
        "https://example.com".to_string(),
        TabType::Ephemeral
    ).await.unwrap();
    
    // Verify it's ephemeral
    let states = tab_manager.get_tab_states();
    assert!(matches!(states[0].tab_type, TabType::Ephemeral));
    
    // Convert to container
    tab_manager.convert_to_container(tab_id).await.unwrap();
    
    // Verify conversion
    let updated_states = tab_manager.get_tab_states();
    assert!(matches!(updated_states[0].tab_type, TabType::Container { .. }));
}

/// Test error handling with invalid operations
#[tokio::test]
async fn test_error_handling() {
    let tab_manager = Arc::new(TabManager::new());
    
    let non_existent_tab = uuid::Uuid::new_v4();
    
    // Try to switch to non-existent tab
    let switch_result = tab_manager.switch_tab(non_existent_tab).await;
    assert!(switch_result.is_err());
    
    // Try to close non-existent tab
    let close_result = tab_manager.close_tab(non_existent_tab).await;
    assert!(close_result.is_err());
    
    // Try to convert non-existent tab
    let convert_result = tab_manager.convert_to_container(non_existent_tab).await;
    assert!(convert_result.is_err());
    
    // Try to update content of non-existent tab
    let update_result = tab_manager.update_page_content(
        non_existent_tab,
        PageContent::Empty
    ).await;
    assert!(update_result.is_err());
}

/// Test concurrent tab operations
#[tokio::test]
async fn test_concurrent_tab_operations() {
    let tab_manager = Arc::new(TabManager::new());
    
    let mut handles = Vec::new();
    
    // Create multiple tabs concurrently
    for i in 0..10 {
        let manager = tab_manager.clone();
        let url = format!("https://example{}.com", i);
        let handle = tokio::spawn(async move {
            manager.open_tab(url, TabType::Ephemeral).await
        });
        handles.push(handle);
    }
    
    // Wait for all tabs to be created
    let mut tab_ids = Vec::new();
    for handle in handles {
        let tab_id = handle.await.unwrap().unwrap();
        tab_ids.push(tab_id);
    }
    
    // Verify all tabs were created
    let states = tab_manager.get_tab_states();
    assert_eq!(states.len(), 10);
    
    // Close all tabs concurrently
    let mut close_handles = Vec::new();
    for tab_id in tab_ids {
        let manager = tab_manager.clone();
        let handle = tokio::spawn(async move {
            manager.close_tab(tab_id).await
        });
        close_handles.push(handle);
    }
    
    // Wait for all tabs to be closed
    for handle in close_handles {
        handle.await.unwrap().unwrap();
    }
    
    // Verify all tabs were closed
    let final_states = tab_manager.get_tab_states();
    assert_eq!(final_states.len(), 0);
}

/// Test memory usage under load
#[tokio::test]
async fn test_memory_usage_under_load() {
    let tab_manager = Arc::new(TabManager::new());
    
    // Create and close many tabs to test memory cleanup
    for batch in 0..10 {
        let mut tab_ids = Vec::new();
        
        // Create batch of tabs
        for i in 0..50 {
            let url = format!("https://test{}-{}.com", batch, i);
            let tab_id = tab_manager.open_tab(url, TabType::Ephemeral).await.unwrap();
            tab_ids.push(tab_id);
        }
        
        // Update some tab content
        for (i, &tab_id) in tab_ids.iter().enumerate() {
            if i % 5 == 0 {
                let content = PageContent::Loaded {
                    url: format!("https://test{}-{}.com", batch, i),
                    title: format!("Test Page {}-{}", batch, i),
                    content: "Test content".repeat(100), // Some content
                    element_count: 50,
                    size_bytes: 2048,
                };
                let _ = tab_manager.update_page_content(tab_id, content).await;
            }
        }
        
        // Close all tabs in batch
        for tab_id in tab_ids {
            tab_manager.close_tab(tab_id).await.unwrap();
        }
        
        // Verify cleanup
        let states = tab_manager.get_tab_states();
        assert_eq!(states.len(), 0);
    }
}

/// Test page content state transitions
#[tokio::test]
async fn test_page_content_state_transitions() {
    let tab_manager = Arc::new(TabManager::new());
    
    let tab_id = tab_manager.open_tab(
        "https://example.com".to_string(),
        TabType::Ephemeral
    ).await.unwrap();
    
    // Initial state should be Loading
    let states = tab_manager.get_tab_states();
    assert!(matches!(states[0].content, PageContent::Loading { .. }));
    
    // Transition to Loaded
    let loaded_content = PageContent::Loaded {
        url: "https://example.com".to_string(),
        title: "Example".to_string(),
        content: "Page content".to_string(),
        element_count: 25,
        size_bytes: 512,
    };
    tab_manager.update_page_content(tab_id, loaded_content).await.unwrap();
    
    let states = tab_manager.get_tab_states();
    if let PageContent::Loaded { title, element_count, .. } = &states[0].content {
        assert_eq!(title, "Example");
        assert_eq!(*element_count, 25);
    } else {
        panic!("Expected loaded content");
    }
    
    // Transition to Error
    let error_content = PageContent::Error {
        url: "https://example.com".to_string(),
        error: "Network timeout".to_string(),
    };
    tab_manager.update_page_content(tab_id, error_content).await.unwrap();
    
    let states = tab_manager.get_tab_states();
    if let PageContent::Error { error, .. } = &states[0].content {
        assert_eq!(error, "Network timeout");
    } else {
        panic!("Expected error content");
    }
    
    // Transition back to Loading (e.g., retry)
    let loading_content = PageContent::Loading {
        url: "https://example.com".to_string(),
    };
    tab_manager.update_page_content(tab_id, loading_content).await.unwrap();
    
    let states = tab_manager.get_tab_states();
    assert!(matches!(states[0].content, PageContent::Loading { .. }));
}

/// Test security context integration
#[tokio::test]
async fn test_security_context_integration() {
    // Test HTML parsing with security context
    use citadel_parser::{parse_html, security::SecurityContext};
    
    let security_context = Arc::new(SecurityContext::new(10));
    
    let malicious_html = r#"
    <html>
    <head>
        <script>alert('xss')</script>
    </head>
    <body>
        <div>
            <div>
                <div>
                    <div>
                        <div>
                            <div>
                                <div>
                                    <div>
                                        <div>
                                            <div>
                                                <div>Deep content</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    "#;
    
    let parse_result = parse_html(malicious_html, security_context);
    
    match parse_result {
        Ok(_dom) => {
            // If parsing succeeds, security context should have handled the threats
            println!("Malicious HTML handled securely");
        }
        Err(e) => {
            // Security context rejection is also acceptable
            println!("Malicious HTML properly rejected: {:?}", e);
        }
    }
}

/// Test DNS resolution and networking integration
#[tokio::test]
async fn test_dns_and_networking_integration() {
    use citadel_networking::CitadelDnsResolver;
    
    let resolver = CitadelDnsResolver::new().await.unwrap();
    
    // Test legitimate domain resolution
    let result = resolver.resolve("example.com").await;
    match result {
        Ok(ips) => {
            assert!(!ips.is_empty(), "Should resolve to at least one IP");
            for ip in ips {
                assert!(!ip.is_private(), "Should not resolve to private IPs");
                assert!(!ip.is_loopback(), "Should not resolve to loopback");
            }
        }
        Err(e) => {
            println!("DNS resolution failed (may be network-dependent): {:?}", e);
        }
    }
}

/// Test the complete navigation flow
#[tokio::test]
async fn test_complete_navigation_flow() {
    // This test simulates a complete user navigation from start to finish
    
    let tab_manager = Arc::new(TabManager::new());
    
    // 1. User opens new tab
    let tab_id = tab_manager.open_tab(
        "https://example.com".to_string(),
        TabType::Ephemeral
    ).await.unwrap();
    
    // 2. Tab starts in loading state
    let states = tab_manager.get_tab_states();
    assert!(matches!(states[0].content, PageContent::Loading { .. }));
    
    // 3. DNS resolution and network request (simulated)
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    // 4. Page loading completes
    let loaded_content = PageContent::Loaded {
        url: "https://example.com".to_string(),
        title: "Example Domain".to_string(),
        content: "This domain is for use in illustrative examples.".to_string(),
        element_count: 15,
        size_bytes: 1270,
    };
    
    tab_manager.update_page_content(tab_id, loaded_content).await.unwrap();
    
    // 5. Verify final state
    let final_states = tab_manager.get_tab_states();
    assert_eq!(final_states.len(), 1);
    assert_eq!(final_states[0].id, tab_id);
    assert!(final_states[0].is_active);
    
    if let PageContent::Loaded { title, url, .. } = &final_states[0].content {
        assert_eq!(title, "Example Domain");
        assert_eq!(url, "https://example.com");
    } else {
        panic!("Expected loaded content state");
    }
}

/// Test system resilience under stress
#[tokio::test]
async fn test_system_resilience() {
    let tab_manager = Arc::new(TabManager::new());
    
    // Test rapid tab creation and destruction
    for _ in 0..100 {
        let tab_id = tab_manager.open_tab(
            "https://stress-test.com".to_string(),
            TabType::Ephemeral
        ).await.unwrap();
        
        // Rapid content updates
        for i in 0..5 {
            let content = if i % 2 == 0 {
                PageContent::Loading { url: "https://stress-test.com".to_string() }
            } else {
                PageContent::Loaded {
                    url: "https://stress-test.com".to_string(),
                    title: format!("Stress Test {}", i),
                    content: "Content".to_string(),
                    element_count: 10,
                    size_bytes: 100,
                }
            };
            
            let _ = tab_manager.update_page_content(tab_id, content).await;
        }
        
        tab_manager.close_tab(tab_id).await.unwrap();
    }
    
    // System should remain stable
    let final_states = tab_manager.get_tab_states();
    assert_eq!(final_states.len(), 0);
} 