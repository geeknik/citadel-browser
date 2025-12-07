//! Comprehensive Security Validation Tests for Citadel Browser
//!
//! This test suite validates the effectiveness of Citadel's antifingerprinting
//! and security protections against common attack vectors and fingerprinting scripts.

use citadel_antifingerprint::*;
use citadel_antifingerprint::metrics::ProtectionType;
use citadel_security::*;
use std::collections::HashMap;

/// Test harness for validating antifingerprinting effectiveness
#[cfg(test)]
mod security_validation_tests {
    use super::*;

    /// Test 1: Canvas Fingerprinting Protection Validation
    #[test]
    fn test_canvas_fingerprinting_resistance() {
        println!("Testing Canvas Fingerprinting Protection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (canvas_prot, _, _, _) = manager.create_protection_modules();

        // Simulate multiple canvas operations that fingerprinters use
        let mut fingerprints = Vec::new();

        for i in 0..10 {
            // Create a canvas fingerprint pattern
            let mut data = vec![0u8; 64];

            // Fill with a pattern that fingerprinters commonly use
            for j in 0..data.len() {
                data[j] = ((i * 7 + j * 13) % 256) as u8;
            }

            // Apply protection - note: the method modifies data in-place
            let mut protected_data = data.clone();
            let result = canvas_prot.protect_image_data(&mut protected_data, 8, 8, "test.com");
            assert!(result.is_ok(), "Canvas protection should succeed");

            fingerprints.extend_from_slice(&protected_data);

            // Verify the data has been modified
            assert_ne!(data, protected_data, "Canvas data should be protected");
        }

        // Collect multiple samples and verify they differ
        let mut unique_fingerprints = std::collections::HashSet::new();

        for sample in 0..5 {
            let mut data = vec![0u8; 32];
            data.fill_with(|| (sample * 31) as u8);

            let mut protected_data = data.clone();
            let result = canvas_prot.protect_image_data(&mut protected_data, 8, 4, "test.com");
            assert!(result.is_ok(), "Canvas protection should succeed");

            let hash = format!("{:x}", md5::compute(&protected_data));
            unique_fingerprints.insert(hash);
        }

        // Should have multiple unique fingerprints due to noise
        assert!(unique_fingerprints.len() > 1, "Canvas fingerprints should vary due to noise");
        println!("✓ Canvas fingerprinting protection working correctly");
    }

    /// Test 2: WebGL Fingerprinting Protection
    #[test]
    fn test_webgl_fingerprinting_protection() {
        println!("Testing WebGL Fingerprinting Protection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, webgl_prot, _, _) = manager.create_protection_modules();

        // Test common WebGL parameters that fingerprinters query
        let original_params = vec![
            ("RENDERER", "ANGLE (Intel, Intel(R) HD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
            ("VENDOR", "Google Inc. (Intel)"),
            ("VERSION", "OpenGL ES 3.0 (WebGL 2.0)"),
            ("SHADING_LANGUAGE_VERSION", "WebGL GLSL ES 3.00"),
        ];

        for (param, value) in original_params {
            let protected = webgl_prot.protect_parameter(param, value);

            // Values should be either normalized or contain noise
            assert!(!protected.is_empty(), "WebGL parameter should not be empty");

            // In maximum protection mode, sensitive info should be spoofed
            if manager.should_protect_feature("webgl") {
                if param == "RENDERER" || param == "VENDOR" {
                    assert_ne!(protected, value, "Sensitive WebGL info should be spoofed");
                }
            }
        }

        println!("✓ WebGL fingerprinting protection validated");
    }

    /// Test 3: Audio Context Fingerprinting Protection
    #[test]
    fn test_audio_fingerprinting_protection() {
        println!("Testing Audio Context Fingerprinting Protection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, _, audio_prot, _) = manager.create_protection_modules();

        // Simulate audio fingerprinting data (frequency domain representation)
        let mut audio_data = vec![0.0f32; 2048];

        // Generate a sine wave pattern that fingerprinters analyze
        for i in 0..audio_data.len() {
            audio_data[i] = (i as f32 * 0.1).sin() * 0.5;
        }

        // Apply protection
        let protected_data = audio_prot.protect_frequency_data(&audio_data, "audio-fingerprint-test.com");

        // Verify noise has been added
        let mut differences = 0;
        for (original, protected) in audio_data.iter().zip(protected_data.iter()) {
            if (original - protected).abs() > 0.001 {
                differences += 1;
            }
        }

        assert!(differences > audio_data.len() / 2, "Audio data should be significantly modified");

        // Test consistency within same domain
        let protected_data_2 = audio_prot.protect_frequency_data(&audio_data, "audio-fingerprint-test.com");

        // Should be consistent for same domain when configured
        assert_eq!(protected_data, protected_data_2, "Audio protection should be consistent for same domain");

        println!("✓ Audio fingerprinting protection working correctly");
    }

    /// Test 4: Navigator Property Normalization
    #[test]
    fn test_navigator_property_normalization() {
        println!("Testing Navigator Property Normalization...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, _, _, nav_prot) = manager.create_protection_modules();

        // Test navigator properties commonly used for fingerprinting
        let test_properties = vec![
            ("userAgent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            ("platform", "Win32"),
            ("hardwareConcurrency", "8"),
            ("deviceMemory", "8"),
            ("language", "en-US"),
            ("languages", "en-US,en"),
            ("doNotTrack", "null"),
        ];

        for (property, value) in test_properties {
            let protected = nav_prot.protect_property(property, value);

            // Properties should be normalized
            assert!(!protected.is_empty(), "Navigator property should not be empty");

            // Check if sensitive properties are normalized
            match property {
                "hardwareConcurrency" | "deviceMemory" => {
                    // These should be standardized to common values
                    assert!(protected == "4" || protected == "8", "Hardware specs should be normalized");
                }
                "userAgent" => {
                    // Should be normalized to reduce entropy
                    let parts: Vec<&str> = protected.split_whitespace().collect();
                    assert!(parts.len() <= 6, "User agent should be simplified");
                }
                _ => {
                    // At minimum, value should be modified
                    if property != "language" { // Keep language for usability
                        assert_ne!(protected, value, "Property should be normalized");
                    }
                }
            }
        }

        println!("✓ Navigator property normalization validated");
    }

    /// Test 5: Security Context and CSP Enforcement
    #[test]
    fn test_security_policy_enforcement() {
        println!("Testing Security Policy Enforcement...");

        let context = SecurityContext::new_default();

        // Test default blocked elements
        assert!(context.is_element_blocked("script"), "Scripts should be blocked by default");
        assert!(context.is_element_blocked("iframe"), "Iframes should be blocked by default");
        assert!(context.is_element_blocked("object"), "Objects should be blocked by default");
        assert!(!context.is_element_blocked("div"), "Div should not be blocked");

        // Test attribute blocking
        assert!(!context.is_attribute_allowed("onclick"), "Event handlers should be blocked");
        assert!(!context.is_attribute_allowed("onerror"), "Error handlers should be blocked");
        assert!(context.is_attribute_allowed("class"), "Class attribute should be allowed");

        // Test CSP configuration
        let csp = context.get_csp();
        assert!(!csp.directives.is_empty(), "CSP should have default directives");

        // Test security headers generation
        let headers = context.generate_security_headers();

        // Should include essential security headers
        assert!(headers.contains_key("Content-Security-Policy"), "CSP header should be generated");
        assert!(headers.contains_key("X-Frame-Options"), "X-Frame-Options should be set");
        assert!(headers.contains_key("X-Content-Type-Options"), "X-Content-Type-Options should be set");
        assert!(headers.contains_key("X-XSS-Protection"), "X-XSS-Protection should be set");

        // Verify header values
        assert_eq!(headers.get("X-Frame-Options").unwrap(), "DENY", "Should deny framing by default");
        assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff", "Should prevent MIME sniffing");

        println!("✓ Security policy enforcement working correctly");
    }

    /// Test 6: Cross-Site Scripting (XSS) Protection
    #[test]
    fn test_xss_protection() {
        println!("Testing XSS Protection...");

        let context = SecurityContext::new_default();

        // Test that scripts are blocked
        assert!(!context.allows_scripts(), "Scripts should be disabled by default");

        // Test that dangerous attributes are blocked
        let xss_attributes = vec![
            "onload", "onerror", "onclick", "onmouseover",
            "onmouseout", "onfocus", "onblur", "onkeydown",
            "onkeyup", "onkeypress", "onsubmit", "onchange"
        ];

        for attr in xss_attributes {
            assert!(!context.is_attribute_allowed(attr), "XSS vector '{}' should be blocked", attr);
        }

        // Test CSP for XSS prevention
        let csp = context.get_csp();

        // Check that unsafe sources are not in default script sources
        if let Some(script_src) = csp.directives.get(&CspDirective::ScriptSrc) {
            assert!(!script_src.contains(&CspSource::UnsafeEval), "Unsafe eval should not be allowed");
            assert!(!script_src.contains(&CspSource::UnsafeInline), "Unsafe inline should not be allowed");
        }

        println!("✓ XSS protection mechanisms validated");
    }

    /// Test 7: Privacy Headers Validation
    #[test]
    fn test_privacy_headers() {
        println!("Testing Privacy Headers...");

        let context = SecurityContext::new_default();
        let headers = context.generate_security_headers();

        // Test referrer policy
        if let Some(referrer_policy) = headers.get("Referrer-Policy") {
            assert!(
                referrer_policy.contains("strict-origin") ||
                referrer_policy.contains("no-referrer"),
                "Referrer policy should be privacy-respecting"
            );
        }

        // Test permissions policy
        if let Some(permissions_policy) = headers.get("Permissions-Policy") {
            // Should disable sensitive APIs by default
            assert!(permissions_policy.contains("camera="), "Camera should be disabled");
            assert!(permissions_policy.contains("microphone="), "Microphone should be disabled");
            assert!(permissions_policy.contains("geolocation="), "Geolocation should be disabled");
        }

        // Test COOP/COEP headers
        assert_eq!(
            headers.get("Cross-Origin-Opener-Policy").unwrap(),
            "same-origin",
            "COOP should restrict cross-origin access"
        );

        assert_eq!(
            headers.get("Cross-Origin-Resource-Policy").unwrap(),
            "same-origin",
            "CORP should restrict cross-origin resource access"
        );

        println!("✓ Privacy headers correctly configured");
    }

    /// Test 8: Domain-Based Fingerprinting Consistency
    #[test]
    fn test_domain_based_fingerprint_consistency() {
        println!("Testing Domain-Based Fingerprint Consistency...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);

        // Test that same domain gets consistent fingerprints
        let domain1 = "example.com";
        let domain2 = "different-site.com";

        // Generate seeds for domains
        let seed1_a = manager.domain_seed(domain1);
        let seed1_b = manager.domain_seed(domain1);
        let seed2_a = manager.domain_seed(domain2);
        let seed2_b = manager.domain_seed(domain2);

        // Same domain should get same seed
        assert_eq!(seed1_a, seed1_b, "Same domain should get consistent seed");
        assert_eq!(seed2_a, seed2_b, "Same domain should get consistent seed");

        // Different domains should get different seeds
        assert_ne!(seed1_a, seed2_a, "Different domains should get different seeds");

        // Test noise application with domain consistency
        let original_value: f64 = 100.0;
        let noise_factor = 0.1;

        let domain1_noise_a = manager.apply_noise(original_value, noise_factor, domain1);
        let domain1_noise_b = manager.apply_noise(original_value, noise_factor, domain1);
        let domain2_noise = manager.apply_noise(original_value, noise_factor, domain2);

        // Same domain should get same noise (for consistency)
        assert_eq!(domain1_noise_a, domain1_noise_b, "Noise should be consistent for same domain");

        // Different domains should get different noise
        assert_ne!(domain1_noise_a, domain2_noise, "Different domains should get different noise");

        println!("✓ Domain-based fingerprint consistency working correctly");
    }

    /// Test 9: Fingerprinting Attack Simulation
    #[test]
    fn test_fingerprinting_attack_simulation() {
        println!("Simulating Fingerprinting Attack...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (canvas_prot, webgl_prot, audio_prot, nav_prot) = manager.create_protection_modules();

        let attacker_domain = "fingerprint-ads.com";
        let mut fingerprint_components = Vec::new();

        // Simulate a comprehensive fingerprinting attack

        // 1. Canvas fingerprinting
        let mut canvas_data = vec![0u8; 256];
        for i in 0..canvas_data.len() {
            canvas_data[i] = (i * 7) as u8;
        }

        let mut protected_canvas = canvas_data.clone();
        let result = canvas_prot.protect_image_data(&mut protected_canvas, 16, 16, attacker_domain);
        assert!(result.is_ok(), "Canvas protection should succeed");

        fingerprint_components.push(format!("canvas:{:x}", md5::compute(&protected_canvas)));

        // 2. WebGL fingerprinting
        let webgl_rend = webgl_prot.protect_parameter("RENDERER", "NVIDIA GeForce RTX 3080");
        let webgl_vendor = webgl_prot.protect_parameter("VENDOR", "NVIDIA Corporation");
        fingerprint_components.push(format!("webgl:{}:{}", webgl_rend, webgl_vendor));

        // 3. Audio fingerprinting
        let mut audio_data = vec![0.0f32; 1024];
        for i in 0..audio_data.len() {
            audio_data[i] = ((i as f32 * 0.05).sin() * 0.5) as f32;
        }
        let protected_audio = audio_prot.protect_frequency_data(&audio_data, attacker_domain);
        fingerprint_components.push(format!("audio:{:x}", md5::compute(&protected_audio)));

        // 4. Navigator fingerprinting
        let user_agent = nav_prot.protect_property("userAgent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        let platform = nav_prot.protect_property("platform", "Win32");
        let cores = nav_prot.protect_property("hardwareConcurrency", "16");
        fingerprint_components.push(format!("nav:{}:{}:{}", user_agent, platform, cores));

        // Combine all components
        let combined_fingerprint = fingerprint_components.join("|");
        let fingerprint_hash = format!("{:x}", md5::compute(combined_fingerprint.as_bytes()));

        // Verify protection is active
        assert!(!fingerprint_hash.is_empty(), "Protected fingerprint should not be empty");

        // Simulate multiple attacks and verify uniqueness
        let mut attack_hashes = std::collections::HashSet::new();

        for i in 0..5 {
            let domain = format!("attacker-{}.com", i);
            let mut canvas = canvas_data.clone();
            let result = canvas_prot.protect_image_data(&mut canvas, 16, 16, &domain);
            assert!(result.is_ok(), "Canvas protection should succeed");

            let hash = format!("{:x}", md5::compute(&canvas));
            attack_hashes.insert(hash);
        }

        // Should have unique fingerprints for different attackers
        assert!(attack_hashes.len() > 1, "Different attackers should get different fingerprints");

        // Record the attack attempt
        manager.record_blocked(ProtectionType::Canvas, attacker_domain);
        manager.record_blocked(ProtectionType::WebGL, attacker_domain);
        manager.record_blocked(ProtectionType::Audio, attacker_domain);

        // Check metrics
        let stats = manager.get_fingerprinting_statistics();
        assert!(!stats.is_empty(), "Fingerprinting attempts should be recorded");

        println!("✓ Fingerprinting attack simulation completed successfully");
        println!("  - Protected fingerprint hash: {}", fingerprint_hash);
        println!("  - Blocked attempts recorded: {}", stats.len());
    }

    /// Test 10: Memory Exhaustion Protection
    #[test]
    fn test_memory_exhaustion_protection() {
        println!("Testing Memory Exhaustion Protection...");

        let context = SecurityContext::new_default();

        // Test reasonable memory requests
        assert!(context.check_memory_usage(1024).is_ok(), "Small memory requests should be allowed");
        assert!(context.check_memory_usage(1024 * 1024).is_ok(), "1MB should be allowed");

        // Test excessive memory requests
        let excessive_size = 512 * 1024 * 1024; // 512MB
        assert!(context.check_memory_usage(excessive_size).is_err(), "Excessive memory requests should be blocked");

        // Check violation was recorded
        let metrics = context.get_metrics();
        assert!(metrics.memory_exhaustion_attempts > 0, "Memory exhaustion attempts should be recorded");

        println!("✓ Memory exhaustion protection working correctly");
    }

    /// Test 11: Advanced Security Configuration
    #[test]
    fn test_advanced_security_configuration() {
        println!("Testing Advanced Security Configuration...");

        let mut context = SecurityContext::new_default();

        // Test default advanced config
        let config = context.get_advanced_config();
        assert!(config.strict_transport_security, "HSTS should be enabled by default");
        assert_eq!(config.frame_options, "DENY", "Should deny framing by default");
        assert_eq!(config.content_type_options, "nosniff", "Should prevent MIME sniffing");

        // Test custom security configuration
        let mut custom_config = AdvancedSecurityConfig::default();
        custom_config.hsts_max_age = 31536000 * 2; // 2 years
        custom_config.referrer_policy = "no-referrer".to_string();

        context.set_advanced_config(custom_config);

        // Generate headers with custom config
        let headers = context.generate_security_headers();

        if let Some(hsts) = headers.get("Strict-Transport-Security") {
            assert!(hsts.contains("max-age=63072000"), "Custom HSTS max-age should be applied");
        }

        if let Some(referrer) = headers.get("Referrer-Policy") {
            assert_eq!(referrer, "no-referrer", "Custom referrer policy should be applied");
        }

        println!("✓ Advanced security configuration validated");
    }

    /// Test 12: Cross-Origin Resource Sharing (CORS) Security
    #[test]
    fn test_cors_security() {
        println!("Testing CORS Security...");

        let context = SecurityContext::new_default();

        // Test that cross-origin requests are properly restricted
        let test_urls = vec![
            "https://malicious-site.com/api/data",
            "http://evil.com/steal-data",
            "data:text/javascript,<script>alert('xss')</script>",
        ];

        for url in test_urls {
            // Should validate URL scheme
            let result = context.validate_url_scheme(url);

            if url.starts_with("http:") {
                // HTTP should be blocked by default (only HTTPS allowed)
                assert!(result.is_err(), "HTTP URLs should be blocked");
            }
        }

        println!("✓ CORS security validated");
    }

    /// Test 13: Protection Level Validation
    #[test]
    fn test_protection_levels() {
        println!("Testing Protection Levels...");

        // Test all protection levels
        let protection_levels = vec![
            ProtectionLevel::Basic,
            ProtectionLevel::Medium,
            ProtectionLevel::Maximum,
        ];

        for level in protection_levels {
            let config = AntiFingerprintConfig {
                enabled: true,
                protection_level: level,
                custom_settings: HashMap::new(),
            };

            let manager = AntiFingerprintManager::new(config);

            // Verify protection level affects feature protection
            match level {
                ProtectionLevel::Basic => {
                    assert!(manager.should_protect_feature("user_agent"), "Basic should protect user agent");
                    // Basic might not protect WebGL
                }
                ProtectionLevel::Medium => {
                    assert!(manager.should_protect_feature("user_agent"), "Medium should protect user agent");
                    assert!(manager.should_protect_feature("canvas"), "Medium should protect canvas");
                }
                ProtectionLevel::Maximum => {
                    assert!(manager.should_protect_feature("user_agent"), "Maximum should protect user agent");
                    assert!(manager.should_protect_feature("canvas"), "Maximum should protect canvas");
                    assert!(manager.should_protect_feature("webgl"), "Maximum should protect WebGL");
                    assert!(manager.should_protect_feature("audio"), "Maximum should protect audio");
                }
            }
        }

        println!("✓ Protection levels validated");
    }

    /// Test 14: Metrics and Monitoring
    #[test]
    fn test_security_metrics() {
        println!("Testing Security Metrics...");

        let config = AntiFingerprintConfig::default();
        let manager = AntiFingerprintManager::new(config);

        // Record various security events
        manager.record_blocked(ProtectionType::Canvas, "tracker.com");
        manager.record_blocked(ProtectionType::WebGL, "fingerprinter.net");
        manager.record_normalized(ProtectionType::Navigator, "analytics.io");

        // Get statistics
        let stats = manager.get_fingerprinting_statistics();
        assert!(!stats.is_empty(), "Statistics should not be empty");

        // Check domain-specific stats
        let tracker_stats = manager.get_domain_statistics("tracker.com");
        assert!(tracker_stats.is_some(), "Should have stats for tracker.com");

        // Export metrics summary
        let summary = manager.export_metrics_summary();
        assert!(summary.total_attempts > 0, "Should record total attempts");

        // Reset metrics
        manager.reset_metrics();
        let empty_stats = manager.get_fingerprinting_statistics();
        assert!(empty_stats.is_empty(), "Stats should be empty after reset");

        println!("✓ Security metrics validated");
    }
}

// Helper function for MD5 computation (simplified for testing)
mod md5 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    pub struct Md5Digest(u64);

    pub fn compute<T: AsRef<[u8]>>(data: T) -> Md5Digest {
        let mut hasher = DefaultHasher::new();
        data.as_ref().hash(&mut hasher);
        Md5Digest(hasher.finish())
    }

    impl std::fmt::LowerHex for Md5Digest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:016x}", self.0)
        }
    }
}