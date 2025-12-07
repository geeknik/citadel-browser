//! Basic security test to verify antifingerprinting works
//!
//! This is a simplified test that demonstrates the key security features
//! are working without relying on external dependencies.

use citadel_antifingerprint::*;
use citadel_security::*;

#[test]
fn test_basic_antifingerprinting() {
    // Test that antifingerprinting is enabled by default
    let config = AntiFingerprintConfig::default();
    assert!(config.enabled, "Antifingerprinting should be enabled");

    let manager = AntiFingerprintManager::new(config);

    // Test that it protects common fingerprinting vectors
    assert!(manager.should_protect_feature("user_agent"), "Should protect user agent");
    assert!(manager.should_protect_feature("canvas"), "Should protect canvas");

    // Test domain-specific seeds
    let seed1 = manager.domain_seed("example.com");
    let seed2 = manager.domain_seed("different.com");
    assert_ne!(seed1, seed2, "Different domains should have different seeds");

    // Test same domain gets same seed
    let seed1_again = manager.domain_seed("example.com");
    assert_eq!(seed1, seed1_again, "Same domain should get consistent seed");

    println!("✓ Basic antifingerprinting test passed");
}

#[test]
fn test_security_context() {
    let context = SecurityContext::new_default();

    // Test dangerous elements are blocked
    assert!(context.is_element_blocked("script"), "Scripts should be blocked");
    assert!(context.is_element_blocked("iframe"), "Iframes should be blocked");

    // Test safe elements are allowed
    assert!(!context.is_element_blocked("div"), "Div should be allowed");
    assert!(!context.is_element_blocked("span"), "Span should be allowed");

    // Test dangerous attributes are blocked
    assert!(!context.is_attribute_allowed("onclick"), "onclick should be blocked");
    assert!(!context.is_attribute_allowed("onload"), "onload should be blocked");

    // Test safe attributes are allowed
    assert!(context.is_attribute_allowed("class"), "class should be allowed");
    assert!(context.is_attribute_allowed("id"), "id should be allowed");

    // Test security headers
    let headers = context.generate_security_headers();
    assert!(headers.contains_key("X-Frame-Options"), "Should have X-Frame-Options");
    assert!(headers.contains_key("X-Content-Type-Options"), "Should have X-Content-Type-Options");

    println!("✓ Security context test passed");
}

#[test]
fn test_protection_levels() {
    // Test that higher protection levels protect more features
    let basic_config = AntiFingerprintConfig {
        enabled: true,
        protection_level: ProtectionLevel::Basic,
        custom_settings: std::collections::HashMap::new(),
    };

    let max_config = AntiFingerprintConfig {
        enabled: true,
        protection_level: ProtectionLevel::Maximum,
        custom_settings: std::collections::HashMap::new(),
    };

    let basic_manager = AntiFingerprintManager::new(basic_config);
    let max_manager = AntiFingerprintManager::new(max_config);

    // Both should protect user agent
    assert!(basic_manager.should_protect_feature("user_agent"));
    assert!(max_manager.should_protect_feature("user_agent"));

    // Maximum should protect more
    assert!(max_manager.should_protect_feature("webgl"));
    assert!(max_manager.should_protect_feature("audio"));

    println!("✓ Protection levels test passed");
}

#[test]
fn test_memory_protection() {
    let context = SecurityContext::new_default();

    // Small allocations should work
    assert!(context.check_memory_usage(1024).is_ok(), "1KB should be allowed");
    assert!(context.check_memory_usage(1024 * 1024).is_ok(), "1MB should be allowed");

    // Very large allocations should be blocked
    assert!(context.check_memory_usage(1024 * 1024 * 1024).is_err(), "1GB should be blocked");

    println!("✓ Memory protection test passed");
}

#[test]
fn test_url_validation() {
    let context = SecurityContext::new_default();

    // HTTPS should be allowed
    assert!(context.validate_url_scheme("https://example.com").is_ok(), "HTTPS should be allowed");

    // Data URLs should be allowed
    assert!(context.validate_url_scheme("data:text/plain,hello").is_ok(), "Data URLs should be allowed");

    // HTTP should be blocked by default
    assert!(context.validate_url_scheme("http://example.com").is_err(), "HTTP should be blocked");

    println!("✓ URL validation test passed");
}