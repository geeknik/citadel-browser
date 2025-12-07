//! Real-world protection tests for Citadel Browser
//!
//! Tests the actual working antifingerprinting capabilities

use citadel_antifingerprint::*;
use citadel_security::*;
use std::collections::HashMap;

#[cfg(test)]
mod real_world_tests {
    use super::*;

    /// Test 1: Verify antifingerprinting is working
    #[test]
    fn test_antifingerprinting_is_enabled() {
        println!("Testing antifingerprinting is enabled by default...");

        let config = AntiFingerprintConfig::default();
        assert!(config.enabled, "Antifingerprinting should be enabled by default");
        assert_eq!(config.protection_level, ProtectionLevel::Medium, "Default protection should be Medium");

        let manager = AntiFingerprintManager::new(config);
        assert!(manager.should_protect_feature("user_agent"), "Should protect user agent");
        assert!(manager.should_protect_feature("canvas"), "Should protect canvas");
        assert!(manager.should_protect_feature("webgl"), "Should protect WebGL at Medium level");
        assert!(manager.should_protect_feature("audio"), "Should protect audio");

        println!("✓ Antifingerprinting is enabled by default with Medium protection");
    }

    /// Test 2: Canvas protection actually modifies data
    #[test]
    fn test_canvas_protection_works() {
        println!("Testing canvas protection modifies data...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (canvas_prot, _, _, _) = manager.create_protection_modules();

        // Create test canvas data
        let mut original_data = vec![128u8; 64]; // Gray pixels
        let mut protected_data = original_data.clone();

        // Apply protection
        let result = canvas_prot.protect_image_data(&mut protected_data, 8, 8, "example.com");
        assert!(result.is_ok(), "Canvas protection should succeed");

        // Data should be modified
        let mut differences = 0;
        for (orig, prot) in original_data.iter().zip(protected_data.iter()) {
            if orig != prot {
                differences += 1;
            }
        }

        assert!(differences > 0, "Canvas data should be modified by protection");
        assert!(differences < original_data.len(), "Not all pixels should be modified");

        // Test position noise
        let (x_noise, y_noise) = canvas_prot.get_text_position_noise(10.0, 20.0, "example.com");
        assert!(x_noise != 10.0 || y_noise != 20.0, "Position should have noise added");

        // Test color noise
        let noisy_color = canvas_prot.get_color_noise(128, "example.com");
        // Color might be the same (low probability) or different
        // We're testing the function works, not that it always changes

        println!("✓ Canvas protection is working and modifying data");
        println!("  - Modified {} out of {} pixels", differences, original_data.len());
    }

    /// Test 3: Audio protection works
    #[test]
    fn test_audio_protection_works() {
        println!("Testing audio protection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, _, audio_prot, _) = manager.create_protection_modules();

        // Test audio buffer protection
        let mut audio_buffer = vec![0.5f32; 1024];
        let result = audio_prot.protect_audio_buffer(&mut audio_buffer, "example.com");
        assert!(result.is_ok(), "Audio buffer protection should succeed");

        // Buffer should be modified
        let mut differences = 0;
        let original_sample = 0.5f32;
        for sample in &audio_buffer {
            if (sample - &original_sample).abs() > 0.0001 {
                differences += 1;
            }
        }
        assert!(differences > 0, "Audio buffer should be modified");

        // Test frequency data protection
        let mut freq_data = vec![128u8; 256];
        let result = audio_prot.protect_frequency_data(&mut freq_data, "example.com");
        assert!(result.is_ok(), "Frequency data protection should succeed");

        // Test audio param normalization
        let audio_params = audio_prot.normalize_audio_params("example.com");
        assert!(!audio_params.context_name.is_empty(), "Audio params should not be empty");
        assert!(audio_params.sample_rate > 0, "Sample rate should be positive");

        println!("✓ Audio protection is working");
        println!("  - Modified {} audio samples", differences);
        println!("  - Normalized sample rate: {}", audio_params.sample_rate);
    }

    /// Test 4: WebGL protection
    #[test]
    fn test_webgl_protection() {
        println!("Testing WebGL protection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, webgl_prot, _, _) = manager.create_protection_modules();

        // Test WebGL parameter protection
        use citadel_antifingerprint::webgl::WebGLParameter;

        let renderer = webgl_prot.get_parameter_value(WebGLParameter::Renderer, "example.com");
        assert!(renderer.is_some(), "Should return a renderer value");

        let vendor = webgl_prot.get_parameter_value(WebGLParameter::Vendor, "example.com");
        assert!(vendor.is_some(), "Should return a vendor value");

        let max_texture = webgl_prot.get_parameter_value(WebGLParameter::MaxTextureSize, "example.com");
        assert!(max_texture.is_some(), "Should return a texture size value");

        // Test shader normalization
        let shader_source = "void main() { gl_Position = vec4(0.0); }";
        let normalized_shader = webgl_prot.normalize_shader(shader_source, "example.com");
        assert!(!normalized_shader.is_empty(), "Normalized shader should not be empty");

        // Test vertex normalization
        let mut vertices = vec![1.0f32, 2.0, 3.0, 4.0];
        let result = webgl_prot.normalize_vertices(&mut vertices, "example.com");
        assert!(result.is_ok(), "Vertex normalization should succeed");

        println!("✓ WebGL protection is working");
        println!("  - Renderer: {}", renderer.unwrap_or_default());
        println!("  - Vendor: {}", vendor.unwrap_or_default());
    }

    /// Test 5: Navigator protection
    #[test]
    fn test_navigator_protection() {
        println!("Testing navigator protection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, _, _, nav_prot) = manager.create_protection_modules();

        // Test user agent normalization
        let real_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let normalized_ua = nav_prot.get_normalized_user_agent(real_ua);

        assert!(!normalized_ua.is_empty(), "Normalized user agent should not be empty");
        assert!(normalized_ua.len() <= real_ua.len() || !normalized_ua.contains("120.0.0.0"),
                "User agent should be simplified");

        // Check that no real version numbers are exposed
        let version_patterns = ["120.0.0.0", "10.0", "Win64", "537.36"];
        for pattern in version_patterns {
            if pattern.contains('.') && pattern.len() > 3 {
                assert!(!normalized_ua.contains(pattern),
                    "Should not expose specific version: {}", pattern);
            }
        }

        println!("✓ Navigator protection is working");
        println!("  - Original: {}", real_ua);
        println!("  - Normalized: {}", normalized_ua);
    }

    /// Test 6: Security context protections
    #[test]
    fn test_security_context() {
        println!("Testing security context protections...");

        let context = SecurityContext::new_default();

        // Verify dangerous elements are blocked
        assert!(context.is_element_blocked("script"), "Scripts should be blocked");
        assert!(context.is_element_blocked("iframe"), "Iframes should be blocked");
        assert!(context.is_element_blocked("object"), "Objects should be blocked");
        assert!(context.is_element_blocked("embed"), "Embeds should be blocked");

        // Verify safe elements are allowed
        assert!(!context.is_element_blocked("div"), "Div should be allowed");
        assert!(!context.is_element_blocked("span"), "Span should be allowed");
        assert!(!context.is_element_blocked("p"), "P should be allowed");

        // Verify dangerous attributes are blocked
        let dangerous_attrs = [
            "onclick", "onload", "onerror", "onmouseover", "onmouseout",
            "onfocus", "onblur", "onkeydown", "onkeyup", "onkeypress",
            "onsubmit", "onchange", "onscroll"
        ];

        for attr in dangerous_attrs {
            assert!(!context.is_attribute_allowed(attr), "Attribute '{}' should be blocked", attr);
        }

        // Verify safe attributes are allowed
        let safe_attrs = ["class", "id", "style", "href", "src", "alt", "title"];
        for attr in safe_attrs {
            assert!(context.is_attribute_allowed(attr), "Attribute '{}' should be allowed", attr);
        }

        // Test security headers
        let headers = context.generate_security_headers();

        assert!(headers.contains_key("Content-Security-Policy"), "Should have CSP header");
        assert!(headers.contains_key("X-Frame-Options"), "Should have X-Frame-Options");
        assert!(headers.contains_key("X-Content-Type-Options"), "Should have X-Content-Type-Options");
        assert!(headers.contains_key("X-XSS-Protection"), "Should have X-XSS-Protection");

        // Verify header values
        assert_eq!(headers.get("X-Frame-Options").unwrap(), "DENY", "Should deny framing");
        assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff", "Should prevent MIME sniffing");

        println!("✓ Security context is properly configured");
        println!("  - Generated {} security headers", headers.len());
    }

    /// Test 7: Fingerprint consistency across domains
    #[test]
    fn test_fingerprint_consistency() {
        println!("Testing fingerprint consistency across domains...");

        let security_context = SecurityContext::new(10);
        let manager = FingerprintManager::new(security_context);

        let domain1 = "example.com";
        let domain2 = "different-site.com";

        // Test domain seeds
        let seed1_a = manager.domain_seed(domain1);
        let seed1_b = manager.domain_seed(domain1);
        let seed2 = manager.domain_seed(domain2);

        assert_eq!(seed1_a, seed1_b, "Same domain should get same seed");
        assert_ne!(seed1_a, seed2, "Different domains should get different seeds");

        // Test noise application
        let test_value: f64 = 100.0;
        let noise_factor = 0.1;

        let noise1_a = manager.apply_noise(test_value, noise_factor, domain1);
        let noise1_b = manager.apply_noise(test_value, noise_factor, domain1);
        let noise2 = manager.apply_noise(test_value, noise_factor, domain2);

        assert_eq!(noise1_a, noise1_b, "Same domain should get same noise");
        assert_ne!(noise1_a, noise2, "Different domains should get different noise");

        println!("✓ Fingerprint consistency is working correctly");
        println!("  - Domain 1 seed: {}", seed1_a);
        println!("  - Domain 2 seed: {}", seed2);
    }

    /// Test 8: Metrics tracking
    #[test]
    fn test_metrics_tracking() {
        println!("Testing metrics tracking...");

        let config = AntiFingerprintConfig::default();
        let manager = AntiFingerprintManager::new(config);

        // Get initial metrics
        let initial_stats = manager.get_fingerprinting_statistics();
        assert_eq!(initial_stats.len(), 0, "Initial stats should be empty");

        // Record some protection events
        manager.record_blocked(ProtectionType::Canvas, "tracker.com");
        manager.record_blocked(ProtectionType::WebGL, "fingerprinter.net");
        manager.record_normalized(ProtectionType::Navigator, "analytics.io");

        // Check updated stats
        let stats = manager.get_fingerprinting_statistics();
        assert!(!stats.is_empty(), "Stats should not be empty after recording events");

        // Check domain-specific stats
        let tracker_stats = manager.get_domain_statistics("tracker.com");
        assert!(tracker_stats.is_some(), "Should have stats for tracker.com");

        // Export metrics summary
        let summary = manager.export_metrics_summary();
        assert!(summary.total_attempts > 0, "Should have total attempts");
        assert!(summary.blocked_attempts > 0, "Should have blocked attempts");
        assert!(summary.canvas_protections > 0, "Should have canvas protections");

        // Reset and verify empty
        manager.reset_metrics();
        let empty_stats = manager.get_fingerprinting_statistics();
        assert_eq!(empty_stats.len(), 0, "Stats should be empty after reset");

        println!("✓ Metrics tracking is working");
        println!("  - Total attempts: {}", summary.total_attempts);
        println!("  - Blocked attempts: {}", summary.blocked_attempts);
    }

    /// Test 9: Protection levels behavior
    #[test]
    fn test_protection_levels() {
        println!("Testing protection levels behavior...");

        let test_cases = vec![
            (ProtectionLevel::None, vec!["user_agent", "platform", "language"]),
            (ProtectionLevel::Basic, vec!["user_agent", "platform", "language"]),
            (ProtectionLevel::Medium, vec!["user_agent", "platform", "language", "canvas", "audio"]),
            (ProtectionLevel::Maximum, vec!["user_agent", "platform", "language", "canvas", "webgl", "audio"]),
        ];

        for (level, expected_protected) in test_cases {
            let config = AntiFingerprintConfig {
                enabled: true,
                protection_level: level,
                custom_settings: HashMap::new(),
            };

            let manager = AntiFingerprintManager::new(config);

            for feature in expected_protected {
                assert!(manager.should_protect_feature(feature),
                    "Protection level {:?} should protect {}", level, feature);
            }
        }

        println!("✓ Protection levels are working correctly");
    }

    /// Test 10: Memory protection
    #[test]
    fn test_memory_protection() {
        println!("Testing memory protection...");

        let context = SecurityContext::new_default();

        // Test normal memory requests
        assert!(context.check_memory_usage(1024).is_ok(), "1KB should be allowed");
        assert!(context.check_memory_usage(1024 * 1024).is_ok(), "1MB should be allowed");
        assert!(context.check_memory_usage(100 * 1024 * 1024).is_ok(), "100MB should be allowed");

        // Test excessive memory request
        let too_much = 1024 * 1024 * 1024; // 1GB
        assert!(context.check_memory_usage(too_much).is_err(), "1GB should be blocked");

        // Check that violation was recorded
        let metrics = context.get_metrics();
        assert!(metrics.memory_exhaustion_attempts > 0, "Memory exhaustion should be recorded");

        println!("✓ Memory protection is working");
        println!("  - Memory exhaustion attempts recorded: {}", metrics.memory_exhaustion_attempts);
    }

    /// Test 11: URL scheme validation
    #[test]
    fn test_url_scheme_validation() {
        println!("Testing URL scheme validation...");

        let context = SecurityContext::new_default();

        // HTTPS should be allowed
        assert!(context.validate_url_scheme("https://example.com").is_ok(), "HTTPS should be allowed");

        // Data URLs should be allowed
        assert!(context.validate_url_scheme("data:text/plain;base64,SGVsbG8=").is_ok(), "Data URLs should be allowed");

        // HTTP should be blocked by default
        assert!(context.validate_url_scheme("http://example.com").is_err(), "HTTP should be blocked");

        // Invalid URLs should be blocked
        assert!(context.validate_url_scheme("not-a-url").is_err(), "Invalid URLs should be blocked");

        println!("✓ URL scheme validation is working");
    }
}

/// Helper for computing simple hashes
mod simple_hash {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    pub struct SimpleHash(u64);

    pub fn compute<T: AsRef<[u8]>>(data: T) -> SimpleHash {
        let mut hasher = DefaultHasher::new();
        data.as_ref().hash(&mut hasher);
        SimpleHash(hasher.finish())
    }

    impl std::fmt::LowerHex for SimpleHash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:016x}", self.0)
        }
    }
}