//! Integration tests for the memory protection system
//!
//! These tests verify that the memory protection system works correctly
//! across all components and integrates properly with the browser engine.

use std::sync::Arc;
use citadel_security::{
    SecurityContext, MemoryProtectionSystem, MemoryProtectionBuilder, 
    ResourceType, MemoryProtectionError
};
use citadel_browser::{BrowserMemoryManager, PerformanceMonitor, MemoryConfig};
use citadel_parser::{ParserMemoryLimits, ParserResourceTracker, ParserMetrics};

#[tokio::test]
async fn test_basic_memory_protection() {
    // Test basic memory protection functionality
    let protection_system = MemoryProtectionBuilder::new()
        .total_memory_limit(10 * 1024 * 1024) // 10MB
        .attack_protection(true)
        .build();
    
    // Normal allocation should work
    let allocation_id = protection_system.allocate(
        ResourceType::DomNodes,
        1024,
        false,
        Some("test".to_string())
    ).unwrap();
    
    assert_eq!(protection_system.total_memory_usage(), 1024);
    
    // Deallocation should work
    protection_system.deallocate(ResourceType::DomNodes, allocation_id).unwrap();
    assert_eq!(protection_system.total_memory_usage(), 0);
}

#[tokio::test]
async fn test_memory_limit_enforcement() {
    // Test that memory limits are properly enforced
    let protection_system = MemoryProtectionBuilder::new()
        .total_memory_limit(2048) // Very small limit for testing
        .build();
    
    // First allocation should work
    let _id1 = protection_system.allocate(ResourceType::GenericMemory, 1000, false, None).unwrap();
    
    // Second allocation should work
    let _id2 = protection_system.allocate(ResourceType::GenericMemory, 900, false, None).unwrap();
    
    // Third allocation should fail - exceeds total limit
    let result = protection_system.allocate(ResourceType::GenericMemory, 200, false, None);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        MemoryProtectionError::MemoryLimitExceeded { .. } => {} // Expected
        e => panic!("Unexpected error type: {:?}", e),
    }
}

#[tokio::test]
async fn test_emergency_cleanup() {
    // Test emergency cleanup functionality
    let protection_system = MemoryProtectionBuilder::new()
        .total_memory_limit(5000)
        .thresholds(0.6, 0.8) // Low thresholds for testing
        .build();
    
    // Fill memory to near limit
    let _id1 = protection_system.allocate(ResourceType::ImageData, 2000, false, None).unwrap();
    let _id2 = protection_system.allocate(ResourceType::ImageData, 2000, false, None).unwrap();
    
    // This should trigger emergency mode
    protection_system.periodic_check();
    assert!(protection_system.is_emergency_mode());
    
    // Force cleanup should free some memory
    let freed = protection_system.force_cleanup(true);
    assert!(freed > 0);
}

#[tokio::test]
async fn test_browser_memory_manager_integration() {
    // Test integration with browser memory manager
    let security_context = Arc::new(SecurityContext::new_default());
    let performance_monitor = Arc::new(PerformanceMonitor::new(MemoryConfig::default()));
    let memory_manager = BrowserMemoryManager::new(security_context, performance_monitor);
    
    // Test DOM memory allocation
    let dom_id = memory_manager.allocate_dom_memory(2048, false).unwrap();
    assert!(memory_manager.total_memory_usage() >= 2048);
    
    // Test JavaScript memory allocation
    let js_id = memory_manager.allocate_js_memory(4096, false).unwrap();
    assert!(memory_manager.total_memory_usage() >= 6144);
    
    // Test cleanup
    memory_manager.deallocate_memory(ResourceType::DomNodes, dom_id).unwrap();
    memory_manager.deallocate_memory(ResourceType::JsObjects, js_id).unwrap();
    
    // Should be back to minimal usage
    assert!(memory_manager.total_memory_usage() < 1024);
}

#[tokio::test]
async fn test_parser_memory_limits() {
    // Test parser-specific memory limits
    let limits = ParserMemoryLimits {
        max_dom_nodes: 10,
        max_parsing_memory: 5000,
        ..Default::default()
    };
    
    let metrics = Arc::new(ParserMetrics::new());
    let mut tracker = ParserResourceTracker::new(limits, metrics);
    
    tracker.start_parsing();
    
    // Add nodes up to limit
    for i in 0..10 {
        tracker.track_dom_node(400).unwrap();
        assert_eq!(tracker.get_current_usage().dom_nodes, i + 1);
    }
    
    // This should fail - exceeds node limit
    let result = tracker.track_dom_node(400);
    assert!(result.is_err());
    
    // Check utilization ratios
    let utilization = tracker.get_utilization_ratios();
    assert!(utilization.dom_nodes >= 1.0); // At or over limit
    assert!(utilization.parsing_memory > 0.5); // Significant memory usage
}

#[tokio::test]
async fn test_tab_memory_management() {
    // Test tab-specific memory management
    let security_context = Arc::new(SecurityContext::new_default());
    let performance_monitor = Arc::new(PerformanceMonitor::new(MemoryConfig::default()));
    let memory_manager = BrowserMemoryManager::new(security_context, performance_monitor);
    
    // Create multiple tabs
    let tab1_id = memory_manager.allocate_tab_memory(1).unwrap();
    let tab2_id = memory_manager.allocate_tab_memory(2).unwrap();
    
    // Allocate memory for each tab
    let dom_id_1 = memory_manager.allocate_dom_memory(1024, false).unwrap();
    let dom_id_2 = memory_manager.allocate_dom_memory(2048, false).unwrap();
    
    // Total memory should include all allocations
    let total = memory_manager.total_memory_usage();
    assert!(total >= 3072); // At least the DOM allocations
    
    // Close first tab
    memory_manager.deallocate_tab_memory(tab1_id).unwrap();
    memory_manager.deallocate_memory(ResourceType::DomNodes, dom_id_1).unwrap();
    
    // Memory should be reduced
    let new_total = memory_manager.total_memory_usage();
    assert!(new_total < total);
    
    // Clean up remaining tab
    memory_manager.deallocate_tab_memory(tab2_id).unwrap();
    memory_manager.deallocate_memory(ResourceType::DomNodes, dom_id_2).unwrap();
}

#[tokio::test]
async fn test_attack_pattern_detection() {
    // Test detection of memory exhaustion attacks
    let protection_system = MemoryProtectionBuilder::new()
        .total_memory_limit(100 * 1024 * 1024) // 100MB
        .attack_protection(true)
        .build();
    
    // Simulate rapid allocation pattern (potential attack)
    for i in 0..2000 {
        let result = protection_system.allocate(
            ResourceType::GenericMemory,
            1024,
            false,
            Some(format!("attack_attempt_{}", i))
        );
        
        if result.is_err() {
            // Attack should be detected and blocked
            break;
        }
        
        if i > 1500 {
            // If we get this far, the system should be in emergency mode
            assert!(protection_system.is_emergency_mode());
            break;
        }
    }
}

#[tokio::test]
async fn test_memory_statistics() {
    // Test memory statistics collection
    let security_context = Arc::new(SecurityContext::new_default());
    let performance_monitor = Arc::new(PerformanceMonitor::new(MemoryConfig::default()));
    let memory_manager = BrowserMemoryManager::new(security_context, performance_monitor);
    
    // Allocate different types of memory
    let _dom_id = memory_manager.allocate_dom_memory(1024, false).unwrap();
    let _js_id = memory_manager.allocate_js_memory(2048, false).unwrap();
    let _img_id = memory_manager.allocate_image_memory(4096).unwrap();
    
    // Get statistics
    let stats = memory_manager.get_memory_statistics();
    
    assert!(stats.total_usage >= 7168);
    assert!(stats.utilization > 0.0);
    assert!(!stats.emergency_mode); // Should not be in emergency mode
    assert!(stats.dom_memory >= 1024);
    assert!(stats.js_memory >= 2048);
    assert!(stats.image_memory >= 4096);
    
    // Test formatted display
    let display = stats.format_for_display();
    assert!(display.contains("Memory Usage:"));
    assert!(display.contains("DOM:"));
    assert!(display.contains("JS:"));
}

#[tokio::test]
async fn test_concurrent_memory_operations() {
    // Test concurrent memory operations for thread safety
    let security_context = Arc::new(SecurityContext::new_default());
    let performance_monitor = Arc::new(PerformanceMonitor::new(MemoryConfig::default()));
    let memory_manager = Arc::new(BrowserMemoryManager::new(security_context, performance_monitor));
    
    let mut handles = Vec::new();
    
    // Spawn multiple tasks doing memory operations
    for i in 0..10 {
        let manager = Arc::clone(&memory_manager);
        let handle = tokio::spawn(async move {
            // Each task allocates and deallocates memory
            let allocation_id = manager.allocate_dom_memory(1024 * (i + 1), false).unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            manager.deallocate_memory(ResourceType::DomNodes, allocation_id).unwrap();
        });
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Memory should be back to minimal usage
    assert!(memory_manager.total_memory_usage() < 1024);
}

#[tokio::test]
async fn test_parser_attack_detection() {
    // Test parser-specific attack detection
    let limits = ParserMemoryLimits::default();
    let metrics = Arc::new(ParserMetrics::new());
    let mut tracker = ParserResourceTracker::new(limits, metrics);
    
    tracker.start_parsing();
    
    // Simulate DOM bomb attack
    for i in 0..1000 {
        let result = tracker.track_dom_node(100);
        if result.is_err() {
            // Should eventually hit the DOM node limit
            break;
        }
        
        if i > 900 {
            // Should be approaching limits
            assert!(tracker.should_throttle());
        }
    }
    
    let utilization = tracker.get_utilization_ratios();
    assert!(utilization.max_utilization() > 0.8); // Should be near limits
}

#[tokio::test]
async fn test_memory_pressure_response() {
    // Test system response to memory pressure
    let protection_system = MemoryProtectionBuilder::new()
        .total_memory_limit(8 * 1024) // 8KB - very small for testing
        .thresholds(0.5, 0.7) // Low thresholds
        .build();
    
    // Fill memory gradually
    let mut allocations = Vec::new();
    
    for i in 0..10 {
        let result = protection_system.allocate(
            ResourceType::ImageData, // Use cleanable resource type
            512,
            false,
            Some(format!("allocation_{}", i))
        );
        
        match result {
            Ok(id) => {
                allocations.push(id);
                
                // Check if we've triggered emergency mode
                protection_system.periodic_check();
                if protection_system.is_emergency_mode() {
                    println!("Emergency mode triggered after {} allocations", i + 1);
                    break;
                }
            }
            Err(_) => {
                // Allocation failed due to memory pressure
                println!("Allocation failed due to memory pressure after {} allocations", i);
                break;
            }
        }
    }
    
    // System should be under memory pressure
    assert!(protection_system.memory_utilization() > 0.5);
}

#[tokio::test]
async fn test_resource_pool_isolation() {
    // Test that different resource pools are properly isolated
    let protection_system = MemoryProtectionBuilder::new()
        .total_memory_limit(100 * 1024 * 1024) // Large total limit
        .build();
    
    // Fill one resource pool
    let mut dom_allocations = Vec::new();
    for i in 0..1000 {
        let result = protection_system.allocate(
            ResourceType::DomNodes,
            1024,
            false,
            Some(format!("dom_{}", i))
        );
        
        match result {
            Ok(id) => dom_allocations.push(id),
            Err(_) => break, // Hit DOM pool limit
        }
    }
    
    // Should still be able to allocate in other pools
    let js_id = protection_system.allocate(
        ResourceType::JsObjects,
        1024,
        false,
        Some("js_test".to_string())
    ).unwrap();
    
    let network_id = protection_system.allocate(
        ResourceType::NetworkConnections,
        1024,
        false,
        Some("network_test".to_string())
    ).unwrap();
    
    // Clean up
    protection_system.deallocate(ResourceType::JsObjects, js_id).unwrap();
    protection_system.deallocate(ResourceType::NetworkConnections, network_id).unwrap();
    
    // Clean up DOM allocations
    for id in dom_allocations {
        let _ = protection_system.deallocate(ResourceType::DomNodes, id);
    }
}

#[tokio::test]
async fn test_critical_allocation_protection() {
    // Test that critical allocations are protected during cleanup
    let protection_system = MemoryProtectionBuilder::new()
        .total_memory_limit(10 * 1024) // 10KB
        .thresholds(0.6, 0.8)
        .build();
    
    // Make critical allocation
    let critical_id = protection_system.allocate(
        ResourceType::DomNodes,
        2048,
        true, // Critical
        Some("critical_allocation".to_string())
    ).unwrap();
    
    // Fill remaining memory with non-critical allocations
    let mut non_critical_ids = Vec::new();
    for i in 0..10 {
        let result = protection_system.allocate(
            ResourceType::ImageData,
            512,
            false, // Non-critical
            Some(format!("non_critical_{}", i))
        );
        
        if let Ok(id) = result {
            non_critical_ids.push(id);
        } else {
            break;
        }
    }
    
    // Trigger cleanup
    protection_system.force_cleanup(true);
    
    // Critical allocation should still be valid
    // (In a real implementation, we'd have a way to verify this)
    let stats = protection_system.get_statistics();
    assert!(stats.get(&ResourceType::DomNodes).unwrap().current_memory >= 2048);
    
    // Clean up
    protection_system.deallocate(ResourceType::DomNodes, critical_id).unwrap();
}