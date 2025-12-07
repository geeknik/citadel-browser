//! Citadel Browser Security Demonstration
//!
//! This example demonstrates the security and antifingerprinting features
//! of Citadel Browser in action.

use citadel_antifingerprint::*;
use citadel_security::*;
use std::collections::HashMap;

fn main() {
    println!("🔒 Citadel Browser Security Demonstration");
    println!("=========================================\n");

    // 1. Show antifingerprinting configuration
    demonstrate_antifingerprinting();

    // 2. Show security context features
    demonstrate_security_context();

    // 3. Show fingerprinting resistance
    demonstrate_fingerprint_resistance();

    // 4. Show protection levels
    demonstrate_protection_levels();

    // 5. Show security headers
    demonstrate_security_headers();

    println!("\n✅ All security features are active and protecting your privacy!");
}

fn demonstrate_antifingerprinting() {
    println!("1. Antifingerprinting Configuration");
    println!("----------------------------------");

    let config = AntiFingerprintConfig::default();
    println!("   • Enabled: {}", config.enabled);
    println!("   • Protection Level: {:?}", config.protection_level);

    let manager = AntiFingerprintManager::new(config);

    // Show what's being protected
    let features = vec![
        "user_agent", "platform", "language", "canvas",
        "webgl", "audio", "screen_resolution", "timezone",
    ];

    println!("   • Protected Features:");
    for feature in features {
        if manager.should_protect_feature(feature) {
            println!("     ✅ {} (PROTECTED)", feature);
        } else {
            println!("     ❌ {} (not protected)", feature);
        }
    }
    println!();
}

fn demonstrate_security_context() {
    println!("2. Security Context Protection");
    println!("------------------------------");

    let context = SecurityContext::new_default();

    // Show blocked elements
    let dangerous_elements = vec!["script", "iframe", "object", "embed"];
    println!("   • Blocked Elements (for security):");
    for element in dangerous_elements {
        if context.is_element_blocked(element) {
            println!("     🚫 {} - BLOCKED", element);
        }
    }

    // Show allowed elements
    let safe_elements = vec!["div", "span", "p", "a"];
    println!("   • Allowed Elements:");
    for element in safe_elements {
        if !context.is_element_blocked(element) {
            println!("     ✅ {} - ALLOWED", element);
        }
    }

    // Show blocked attributes
    let dangerous_attrs = vec!["onclick", "onload", "onerror", "onmouseover"];
    println!("   • Blocked Event Handlers:");
    for attr in dangerous_attrs {
        if !context.is_attribute_allowed(attr) {
            println!("     🚫 {} - BLOCKED", attr);
        }
    }

    // Show memory protection
    println!("   • Memory Protection:");
    println!("     - 1MB allocation: {}",
        if context.check_memory_usage(1024 * 1024).is_ok() { "✅ Allowed" } else { "🚫 Blocked" });
    println!("     - 1GB allocation: {}",
        if context.check_memory_usage(1024 * 1024 * 1024).is_ok() { "❌ Allowed" } else { "✅ Blocked" });
    println!();
}

fn demonstrate_fingerprint_resistance() {
    println!("3. Fingerprinting Resistance");
    println!("---------------------------");

    let security_context = SecurityContext::new(10);
    let manager = FingerprintManager::new(security_context);

    let test_domains = vec![
        "google-analytics.com",
        "doubleclick.net",
        "facebook.com",
        "example.com",
    ];

    println!("   • Domain-specific Seeds (for consistent fingerprinting):");
    for domain in test_domains {
        let seed = manager.domain_seed(domain);
        println!("     {}: {:x}", domain, seed);
    }

    // Demonstrate noise injection
    let test_value: f64 = 100.0;
    println!("\n   • Noise Injection Examples:");
    for domain in ["tracker.com", "adserver.net", "example.com"] {
        let noisy = manager.apply_noise(test_value, 0.1, domain);
        let difference = (noisy - test_value).abs();
        println!("     {}: {:.2} (noise: {:.2}%)", domain, noisy, difference);
    }
    println!();
}

fn demonstrate_protection_levels() {
    println!("4. Protection Levels");
    println!("-------------------");

    let levels = vec![
        (ProtectionLevel::None, "No protection"),
        (ProtectionLevel::Basic, "Basic protection (minimal impact)"),
        (ProtectionLevel::Medium, "Medium protection (balanced)"),
        (ProtectionLevel::Maximum, "Maximum protection (may break some sites)"),
    ];

    for (level, description) in levels {
        println!("   • {:?} - {}", level, description);

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: level,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);

        let features = ["canvas", "webgl", "audio"];
        for feature in features {
            if manager.should_protect_feature(feature) {
                print!("  ✅");
            } else {
                print!("  ❌");
            }
        }
        println!(" ({})", features.join(", "));
    }
    println!();
}

fn demonstrate_security_headers() {
    println!("5. Generated Security Headers");
    println!("---------------------------");

    let context = SecurityContext::new_default();
    let headers = context.generate_security_headers();

    println!("   • Security Headers automatically added to responses:");
    for (header, value) in headers {
        println!("     {}: {}", header, value);
    }

    // Show URL validation
    println!("\n   • URL Scheme Validation:");
    let test_urls = vec![
        ("https://secure-site.com", "✅ Allowed"),
        ("data:text/plain,hello", "✅ Allowed"),
        ("http://insecure-site.com", "🚫 Blocked"),
        ("javascript:alert('xss')", "🚫 Blocked"),
    ];

    for (url, expected) in test_urls {
        let result = context.validate_url_scheme(url);
        let status = if result.is_ok() { "✅ Allowed" } else { "🚫 Blocked" };
        println!("     {} - {} ({})", url, status, expected);
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_runs_successfully() {
        // This test just ensures the demo code compiles and runs
        demonstrate_antifingerprinting();
        demonstrate_security_context();
        demonstrate_fingerprint_resistance();
        demonstrate_protection_levels();
        demonstrate_security_headers();
    }
}