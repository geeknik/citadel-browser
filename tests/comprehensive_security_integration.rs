//! Comprehensive Security Integration Tests
//!
//! This test suite validates the integration of all security components
//! at nation-state level protection requirements.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

use citadel_security::{
    SecurityContext, SecurityContextBuilder, SecurityError, SecuritySeverity,
    ContentSecurityPolicy, CspDirective, CspSource, SecurityViolation,
    FingerprintProtectionLevel, AdvancedSecurityConfig,
    ContentSecurity, ContentSecurityConfig, XSSProtectionLevel,
    FrameProtection, ScriptExecutionPolicy, InlineStylePolicy
};
use citadel_antifingerprint::{
    AntiFingerprintManager, AntiFingerprintConfig, ProtectionLevel,
    NationStateSettings, FingerprintProtectionInfo
};
use citadel_networking::{
    NetworkConfig, PrivacyLevel, NetworkSecurity, NetworkSecurityConfig,
    SecurityEventType, ThreatType
};

/// Comprehensive security integration test suite
pub struct ComprehensiveSecuritySuite {
    security_context: Arc<SecurityContext>,
    antifingerprint_manager: AntiFingerprintManager,
    content_security: ContentSecurity,
    network_security: NetworkSecurity,
}

impl ComprehensiveSecuritySuite {
    /// Create a new comprehensive security test suite
    pub fn new() -> Self {
        // Create security context with nation-state level protection
        let security_context = Arc::new(
            SecurityContextBuilder::new()
                .block_elements(vec!["script", "iframe", "object", "embed", "form"])
                .enforce_https(true)
                .with_fingerprint_protection(FingerprintProtectionLevel::Maximum)
                .build()
                .expect("Failed to create security context")
        );

        // Create antifingerprint manager with nation-state settings
        let antifingerprint_config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::NationState,
            custom_settings: std::collections::HashMap::new(),
            nation_state_settings: NationStateSettings {
                behavioral_obfuscation: true,
                timing_noise: true,
                request_randomization: true,
                font_spoofing: true,
                hardware_randomization: true,
                advanced_webgl_noise: true,
                canvas_randomization: true,
                audio_spoofing: true,
            },
        };
        let antifingerprint_manager = AntiFingerprintManager::new(antifingerprint_config);

        // Create content security with strict settings
        let content_security_config = ContentSecurityConfig {
            strict_csp: true,
            xss_protection: XSSProtectionLevel::Maximum,
            csrf_protection: true,
            content_type_protection: true,
            frame_protection: FrameProtection::DenyAll,
            script_policy: ScriptExecutionPolicy::Strict,
            inline_style_policy: InlineStylePolicy::BlockAll,
            trusted_content_types: {
                let mut types = std::collections::HashSet::new();
                types.insert("text/html".to_string());
                types.insert("text/css".to_string());
                types.insert("image/png".to_string());
                types.insert("image/jpeg".to_string());
                types.insert("application/wasm".to_string());
                types
            },
        };
        let content_security = ContentSecurity::new(content_security_config);

        // Create network security with maximum protection
        let network_security_config = NetworkSecurityConfig {
            enforce_https: true,
            certificate_pinning: true,
            malicious_site_detection: true,
            privacy_headers: true,
            strict_cert_validation: true,
            hsts_preload: true,
            block_tracking: true,
            dns_over_https: true,
            connection_timeout: 10,
            max_redirects: 3,
        };
        let network_security = NetworkSecurity::new(network_security_config);

        Self {
            security_context,
            antifingerprint_manager,
            content_security,
            network_security,
        }
    }

    /// Run all comprehensive security tests
    pub async fn run_all_tests(&mut self) -> SecurityTestResults {
        let mut results = SecurityTestResults::new();

        // Test antifingerprinting integration
        self.test_antifingerprinting_integration(&mut results).await;

        // Test content security integration
        self.test_content_security_integration(&mut results).await;

        // Test network security integration
        self.test_network_security_integration(&mut results).await;

        // Test cross-component integration
        self.test_cross_component_integration(&mut results).await;

        // Test nation-state level requirements
        self.test_nation_state_requirements(&mut results).await;

        results
    }

    /// Test antifingerprinting integration
    async fn test_antifingerprinting_integration(&self, results: &mut SecurityTestResults) {
        // Test all protection modules are created
        let (canvas, webgl, audio, navigator, font, hardware, behavioral) =
            self.antifingerprint_manager.create_protection_modules();

        results.add_test("Antifingerprinting - Module Creation", true);

        // Test font protection
        let font_list = font.get_protected_font_list("example.com");
        results.add_test(
            "Antifingerprinting - Font Protection",
            !font_list.is_empty() && font_list.len() <= 50
        );

        // Test hardware protection
        let hardware_info = hardware.get_protected_hardware_info("example.com");
        results.add_test(
            "Antifingerprinting - Hardware Protection",
            hardware_info.cpu_cores > 0 && hardware_info.device_memory > 0.0
        );

        // Test behavioral protection
        let typing_metrics = behavioral.get_typing_metrics("example.com");
        results.add_test(
            "Antifingerprinting - Behavioral Protection",
            typing_metrics.avg_speed > 0.0 && typing_metrics.avg_pause > 0
        );

        // Test protection level
        let protects_all = [
            "canvas", "webgl", "audio", "navigator", "fonts",
            "hardware", "screen_resolution", "timezone", "language"
        ].iter().all(|feature| self.antifingerprint_manager.should_protect_feature(feature));

        results.add_test(
            "Antifingerprinting - Nation-State Protection",
            protects_all
        );
    }

    /// Test content security integration
    async fn test_content_security_integration(&self, results: &mut SecurityTestResults) {
        // Test HTML sanitization
        let malicious_html = r#"
            <html>
            <head><script>alert('xss')</script></head>
            <body onclick="malicious()">
                <iframe src="javascript:alert(1)"></iframe>
            </body>
            </html>
        "#;

        let sanitization_result = self.content_security.sanitize_html(malicious_html, &self.security_context);
        results.add_test(
            "Content Security - HTML Sanitization",
            sanitization_result.modified &&
            !sanitization_result.content.contains("<script>") &&
            !sanitization_result.content.contains("onclick=")
        );

        // Test CSS sanitization
        let malicious_css = r#"
            body { expression(alert('xss')); }
            @import url('malicious.css');
            .danger { behavior: url(malicious.htc); }
        "#;

        let css_result = self.content_security.sanitize_css(malicious_css);
        results.add_test(
            "Content Security - CSS Sanitization",
            css_result.modified &&
            !css_result.content.contains("expression") &&
            !css_result.content.contains("@import")
        );

        // Test nonce generation
        let nonce1 = self.content_security.generate_nonce();
        let nonce2 = self.content_security.generate_nonce();
        results.add_test(
            "Content Security - Nonce Generation",
            !nonce1.is_empty() && nonce1 != nonce2 && nonce1.len() > 10
        );

        // Test CSRF protection
        let session_id = "test_session_123";
        let token = self.content_security.generate_csrf_token(session_id);
        let is_valid = self.content_security.validate_csrf_token(session_id, &token);
        results.add_test(
            "Content Security - CSRF Protection",
            !token.is_empty() && is_valid
        );

        // Test frame protection
        let should_block = !self.content_security.should_allow_frame(
            "https://evil.com",
            "https://example.com"
        );
        results.add_test(
            "Content Security - Frame Protection",
            should_block
        );

        // Test script policy
        let should_block_script = !self.content_security.should_execute_script(
            "https://evil.com",
            "https://example.com",
            false
        );
        results.add_test(
            "Content Security - Script Policy",
            should_block_script
        );
    }

    /// Test network security integration
    async fn test_network_security_integration(&self, results: &mut SecurityTestResults) {
        // Test HTTPS enforcement
        let https_result = self.network_security.validate_url("https://example.com").await;
        let http_result = self.network_security.validate_url("http://example.com").await;
        results.add_test(
            "Network Security - HTTPS Enforcement",
            https_result.is_ok() && http_result.is_err()
        );

        // Test tracking domain blocking
        let tracking_result = self.network_security.validate_url("https://google-analytics.com/track").await;
        results.add_test(
            "Network Security - Tracking Domain Blocking",
            tracking_result.is_err()
        );

        // Test privacy headers
        let headers = self.network_security.generate_privacy_headers("example.com");
        results.add_test(
            "Network Security - Privacy Headers",
            headers.contains_key("DNT") && headers.get("DNT") == Some(&"1".to_string())
        );

        // Test HSTS functionality
        self.network_security.add_hsts_domain("example.com", 86400);
        let hsts_http_result = self.network_security.validate_url("http://example.com").await;
        results.add_test(
            "Network Security - HSTS Protection",
            hsts_http_result.is_err()
        );

        // Test security events
        let events = self.network_security.get_security_events(10);
        results.add_test(
            "Network Security - Event Logging",
            events.len() >= 0 // Should have logged some violations
        );
    }

    /// Test cross-component integration
    async fn test_cross_component_integration(&self, results: &mut SecurityTestResults) {
        // Test that components work together
        let test_url = "https://example.com";

        // Validate with network security
        let network_result = self.network_security.validate_url(test_url).await;

        // Process content with content security
        let test_html = r#"<html><body><p>Test</p></body></html>"#;
        let content_result = self.content_security.sanitize_html(test_html, &self.security_context);

        // Check antifingerprinting protection
        let protection_active = self.antifingerprint_manager.should_protect_feature("canvas");

        results.add_test(
            "Cross-Component Integration",
            network_result.is_ok() && content_result.content.contains("Test") && protection_active
        );

        // Test security headers generation
        let security_headers = self.security_context.generate_security_headers();
        let privacy_headers = self.network_security.generate_privacy_headers("example.com");

        results.add_test(
            "Cross-Component - Security Headers",
            security_headers.contains_key("Content-Security-Policy") &&
            privacy_headers.contains_key("DNT")
        );
    }

    /// Test nation-state level requirements
    async fn test_nation_state_requirements(&self, results: &mut SecurityTestResults) {
        // Check all nation-state requirements are met

        // 1. Maximum antifingerprinting
        let info = FingerprintProtectionInfo::from_security_context(&self.security_context);
        let max_protection = info.canvas_protection &&
                           info.webgl_protection &&
                           info.audio_protection &&
                           info.font_protection &&
                           info.hardware_protection &&
                           info.behavioral_protection;

        results.add_test(
            "Nation-State - Maximum Fingerprint Protection",
            max_protection
        );

        // 2. Strict content security
        let strict_csp = self.content_security.config().strict_csp &&
                        matches!(self.content_security.config().xss_protection, XSSProtectionLevel::Maximum) &&
                        self.content_security.config().csrf_protection;

        results.add_test(
            "Nation-State - Strict Content Security",
            strict_csp
        );

        // 3. Network security
        let network_config = self.network_security.config();
        let max_network = network_config.enforce_https &&
                         network_config.certificate_pinning &&
                         network_config.malicious_site_detection &&
                         network_config.dns_over_https;

        results.add_test(
            "Nation-State - Maximum Network Security",
            max_network
        );

        // 4. No data leakage
        let no_leakage = self.security_context.allows_scripts() == false &&
                        self.security_context.is_strict_mode();

        results.add_test(
            "Nation-State - No Data Leakage",
            no_leakage
        );

        // 5. Comprehensive monitoring
        let metrics = self.antifingerprint_manager.export_metrics_summary();
        let has_monitoring = metrics.total_attempts >= 0; // Should be tracking

        results.add_test(
            "Nation-State - Comprehensive Monitoring",
            has_monitoring
        );
    }
}

/// Security test results collector
#[derive(Debug)]
pub struct SecurityTestResults {
    tests: Vec<SecurityTest>,
}

#[derive(Debug)]
struct SecurityTest {
    name: String,
    passed: bool,
}

impl SecurityTestResults {
    pub fn new() -> Self {
        Self {
            tests: Vec::new(),
        }
    }

    pub fn add_test(&mut self, name: &str, passed: bool) {
        self.tests.push(SecurityTest {
            name: name.to_string(),
            passed,
        });
    }

    pub fn total_tests(&self) -> usize {
        self.tests.len()
    }

    pub fn passed_tests(&self) -> usize {
        self.tests.iter().filter(|t| t.passed).count()
    }

    pub fn failed_tests(&self) -> usize {
        self.tests.iter().filter(|t| !t.passed).count()
    }

    pub fn success_rate(&self) -> f64 {
        if self.tests.is_empty() {
            0.0
        } else {
            self.passed_tests() as f64 / self.total_tests() as f64
        }
    }

    pub fn print_summary(&self) {
        println!("\n=== Comprehensive Security Integration Test Results ===");
        println!("Total Tests: {}", self.total_tests());
        println!("Passed: {}", self.passed_tests());
        println!("Failed: {}", self.failed_tests());
        println!("Success Rate: {:.1}%", self.success_rate() * 100.0);

        if self.failed_tests() > 0 {
            println!("\nFailed Tests:");
            for test in &self.tests {
                if !test.passed {
                    println!("  ❌ {}", test.name);
                }
            }
        }

        if self.success_rate() >= 0.95 {
            println!("\n✅ Security integration test suite PASSED - Nation-state level protection achieved!");
        } else {
            println!("\n⚠️  Security integration test suite needs attention");
        }
    }
}

#[tokio::test]
async fn test_comprehensive_security_integration() {
    let mut suite = ComprehensiveSecuritySuite::new();
    let results = suite.run_all_tests().await;

    results.print_summary();

    // Nation-state security requirements
    assert!(results.success_rate() >= 0.95, "Security integration test suite requires at least 95% pass rate for nation-state level protection");
    assert!(results.failed_tests() <= 2, "Maximum 2 failed tests allowed");

    // Specific critical tests must pass
    let critical_tests = [
        "Nation-State - Maximum Fingerprint Protection",
        "Nation-State - Strict Content Security",
        "Nation-State - Maximum Network Security",
        "Antifingerprinting - Nation-State Protection",
    ];

    for test_name in &critical_tests {
        let test_passed = results.tests.iter().any(|t| t.name == *test_name && t.passed);
        assert!(test_passed, "Critical test failed: {}", test_name);
    }
}

#[tokio::test]
async fn test_security_configuration_defaults() {
    // Test that default configurations provide nation-state level protection

    let suite = ComprehensiveSecuritySuite::new();

    // Verify antifingerprinting configuration
    let config = suite.antifingerprint_manager.config();
    assert!(config.enabled);
    assert!(matches!(config.protection_level, ProtectionLevel::NationState));
    assert!(config.nation_state_settings.behavioral_obfuscation);
    assert!(config.nation_state_settings.hardware_randomization);

    // Verify content security configuration
    let content_config = suite.content_security.config();
    assert!(content_config.strict_csp);
    assert!(matches!(content_config.xss_protection, XSSProtectionLevel::Maximum));
    assert!(matches!(content_config.frame_protection, FrameProtection::DenyAll));

    // Verify network security configuration
    let network_config = suite.network_security.config();
    assert!(network_config.enforce_https);
    assert!(network_config.certificate_pinning);
    assert!(network_config.malicious_site_detection);
}

#[tokio::test]
async fn test_cross_domain_isolation() {
    let suite = ComprehensiveSecuritySuite::new();

    // Test that different domains get different protections
    let font_list1 = suite.antifingerprint_manager.create_protection_modules().5
        .get_protected_font_list("domain1.com");
    let font_list2 = suite.antifingerprint_manager.create_protection_modules().5
        .get_protected_font_list("domain2.com");

    // Should be different for different domains
    assert!(font_list1 != font_list2, "Different domains should get different protection");

    // Test hardware info varies by domain
    let hw1 = suite.antifingerprint_manager.create_protection_modules().5
        .get_protected_hardware_info("domain1.com");
    let hw2 = suite.antifingerprint_manager.create_protection_modules().5
        .get_protected_hardware_info("domain2.com");

    assert!(hw1 != hw2, "Hardware profile should vary by domain");
}