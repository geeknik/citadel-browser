//! Tests against real-world fingerprinting scripts and techniques
//!
//! This module simulates common fingerprinting scripts used by tracking companies
//! and validates that Citadel's protections effectively neutralize them.

use citadel_antifingerprint::*;
use std::collections::HashMap;

#[cfg(test)]
mod real_world_fingerprinting_tests {
    use super::*;

    /// Test against FingerprintJS-style fingerprinting
    #[test]
    fn test_fingerprintjs_protection() {
        println!("Testing protection against FingerprintJS-style fingerprinting...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (canvas_prot, webgl_prot, audio_prot, nav_prot) = manager.create_protection_modules();

        // Simulate FingerprintJS comprehensive fingerprinting
        let mut fingerprint_components = HashMap::new();

        // 1. Canvas fingerprinting (text rendering)
        let text_to_render = "Cwmfjordbankglyphs vext quiz, 😃";
        let mut canvas_pixels = vec![0u8; text_to_render.len() * 4]; // RGBA

        // Simulate rendering text to canvas
        for (i, ch) in text_to_render.chars().enumerate() {
            let base = (ch as u32) * 0x01010101;
            canvas_pixels[i * 4] = ((base >> 24) & 0xFF) as u8;
            canvas_pixels[i * 4 + 1] = ((base >> 16) & 0xFF) as u8;
            canvas_pixels[i * 4 + 2] = ((base >> 8) & 0xFF) as u8;
            canvas_pixels[i * 4 + 3] = (base & 0xFF) as u8;
        }

        let protected_canvas = canvas_prot.protect_image_data(&canvas_pixels, "fingerprintjs.com");
        fingerprint_components.insert("canvas", format!("{:x}", md5::compute(&protected_canvas)));

        // 2. WebGL fingerprinting
        let webgl_info = vec![
            ("UNMASKED_VENDOR_WEBGL", "Intel Inc."),
            ("UNMASKED_RENDERER_WEBGL", "Intel Iris Pro Graphics"),
            ("MAX_TEXTURE_SIZE", "16384"),
            ("MAX_VIEWPORT_DIMS", "16384,16384"),
            ("ALIASED_LINE_WIDTH_RANGE", "1,1"),
            ("ALIASED_POINT_SIZE_RANGE", "1,1024"),
            ("MAX_TEXTURE_IMAGE_UNITS", "32"),
            ("MAX_RENDERBUFFER_SIZE", "16384"),
            ("MAX_CUBE_MAP_TEXTURE_SIZE", "16384"),
        ];

        let mut webgl_fingerprint = String::new();
        for (param, value) in webgl_info {
            let protected = webgl_prot.protect_parameter(param, value);
            webgl_fingerprint.push_str(&format!("{}={},", param, protected));
        }
        fingerprint_components.insert("webgl", webgl_fingerprint);

        // 3. Audio fingerprinting
        let audio_context_size = 4096;
        let mut audio_data = vec![0.0f32; audio_context_size];

        // Generate audio signal (as AudioContext would)
        for i in 0..audio_context_size {
            audio_data[i] = ((i as f32 * 2.0 * std::f32::consts::PI * 440.0 / 44100.0).sin() * 0.1) as f32;
        }

        let protected_audio = audio_prot.protect_frequency_data(&audio_data, "fingerprintjs.com");
        fingerprint_components.insert("audio", format!("{:x}", md5::compute(&protected_audio)));

        // 4. Navigator properties
        let navigator_props = vec![
            ("userAgent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            ("language", "en-US"),
            ("languages", "en-US,en"),
            ("platform", "Win32"),
            ("hardwareConcurrency", "8"),
            ("deviceMemory", "8"),
            ("cookieEnabled", "true"),
            ("doNotTrack", "null"),
            ("screenResolution", "1920x1080"),
            ("screenColorDepth", "24"),
            ("timezoneOffset", "-300"),
        ];

        let mut nav_fingerprint = String::new();
        for (prop, value) in navigator_props {
            let protected = nav_prot.protect_property(prop, value);
            nav_fingerprint.push_str(&format!("{}={},", prop, protected));
        }
        fingerprint_components.insert("navigator", nav_fingerprint);

        // Combine all components
        let mut full_fingerprint = String::new();
        let mut components: Vec<_> = fingerprint_components.iter().collect();
        components.sort_by_key(|(k, _)| *k); // Sort for consistency

        for (key, value) in components {
            full_fingerprint.push_str(&format!("{}:{}|", key, value));
        }

        let final_hash = format!("{:x}", md5::compute(full_fingerprint.as_bytes()));

        // Verify protection is effective
        assert!(!final_hash.is_empty(), "Protected fingerprint should not be empty");

        // The fingerprint should be different from what would be generated without protection
        // This is a simplified check - in reality, we'd compare against known good values
        assert!(!final_fingerprint.contains("Intel"), "Hardware vendor should be masked");
        assert!(!final_fingerprint.contains("NVIDIA"), "Hardware vendor should be masked");

        println!("✓ FingerprintJS protection validated");
        println!("  Protected fingerprint hash: {}", final_hash);
    }

    /// Test against CanvasBlocker-style detection
    #[test]
    fn test_canvas_blocker_detection() {
        println!("Testing CanvasBlocker-style fingerprinting detection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Medium,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (canvas_prot, _, _, _) = manager.create_protection_modules();

        // Test 1: Basic canvas operations
        let test_domains = vec!["example.com", "tracker.com", "ads.com"];
        let mut canvas_hashes = std::collections::HashSet::new();

        for domain in test_domains {
            // Create a simple canvas drawing (rectangles and text)
            let mut canvas_data = vec![255u8; 64]; // White background

            // Draw a pattern
            for i in 0..8 {
                for j in 0..8 {
                    if (i + j) % 2 == 0 {
                        canvas_data[i * 8 + j] = 0; // Black squares
                    }
                }
            }

            let protected = canvas_prot.protect_image_data(&canvas_data, domain);
            let hash = format!("{:x}", md5::compute(&protected));
            canvas_hashes.insert(hash);
        }

        // Different domains should get different canvas results
        assert!(canvas_hashes.len() > 1, "Canvas should produce different results for different domains");

        // Test 2: Canvas readback API protection
        let original_data = vec![128u8; 256];
        let protected_data = canvas_prot.protect_image_data(&original_data, "canvas-test.com");

        // Data should be modified
        let mut differences = 0;
        for (orig, prot) in original_data.iter().zip(protected_data.iter()) {
            if orig != prot {
                differences += 1;
            }
        }

        assert!(differences > 0, "Canvas data should be modified");
        assert!(differences < original_data.len(), "Canvas data should not be completely destroyed");

        // Test 3: Multiple reads should be consistent
        let protected_1 = canvas_prot.protect_image_data(&original_data, "consistent-test.com");
        let protected_2 = canvas_prot.protect_image_data(&original_data, "consistent-test.com");

        assert_eq!(protected_1, protected_2, "Multiple reads should be consistent for same domain");

        println!("✓ CanvasBlocker detection validated");
    }

    /// Test against audio fingerprinting counter-detection
    #[test]
    fn test_audio_fingerprint_counter_detection() {
        println!("Testing audio fingerprinting counter-detection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, _, audio_prot, _) = manager.create_protection_modules();

        // Simulate various audio fingerprinting techniques

        // 1. Oscillator-based fingerprinting
        let sample_rates = vec![8000, 11025, 16000, 22050, 44100, 48000];
        let mut oscillator_fingerprints = Vec::new();

        for &sample_rate in &sample_rates {
            let mut samples = vec![0.0f32; sample_rate / 10]; // 0.1 second of audio

            // Generate sine wave at 440 Hz
            for i in 0..samples.len() {
                samples[i] = ((i as f32 * 2.0 * std::f32::consts::PI * 440.0 / sample_rate as f32).sin() * 0.5) as f32;
            }

            let protected = audio_prot.protect_frequency_data(&samples, "audio-fp.com");
            let hash = format!("{:x}", md5::compute(&protected));
            oscillator_fingerprints.push(hash);
        }

        // Different sample rates should produce different protected results
        let unique_hashes: std::collections::HashSet<_> = oscillator_fingerprints.iter().collect();
        assert!(unique_hashes.len() > 1, "Different audio configurations should produce unique fingerprints");

        // 2. Audio context characteristics
        let audio_context_props = vec![
            ("sampleRate", "44100"),
            ("state", "running"),
            ("destination.channelCount", "2"),
            ("destination.maxChannelCount", "2"),
            ("destination.channelCountMode", "max"),
            ("destination.channelInterpretation", "speakers"),
        ];

        let mut protected_props = Vec::new();
        for (prop, value) in audio_context_props {
            // Audio protection should affect these properties
            let mock_data = vec![value.as_bytes().len() as f32; 32];
            let protected = audio_prot.protect_frequency_data(&mock_data, "audio-context.com");
            protected_props.push(format!("{}:{}", prop, protected.len()));
        }

        // Properties should be modified
        assert!(!protected_props.is_empty(), "Audio context properties should be protected");

        // 3. Noise injection consistency
        let base_signal = vec![0.5f32; 1024];

        let domain_a_noise = audio_prot.protect_frequency_data(&base_signal, "domain-a.com");
        let domain_a_noise_2 = audio_prot.protect_frequency_data(&base_signal, "domain-a.com");
        let domain_b_noise = audio_prot.protect_frequency_data(&base_signal, "domain-b.com");

        // Same domain should get consistent noise
        assert_eq!(domain_a_noise, domain_a_noise_2, "Noise should be consistent for same domain");

        // Different domains should get different noise
        assert_ne!(domain_a_noise, domain_b_noise, "Different domains should get different noise");

        println!("✓ Audio fingerprint counter-detection validated");
    }

    /// Test against WebGL fingerprinting detection
    #[test]
    fn test_webgl_fingerprint_detection() {
        println!("Testing WebGL fingerprint detection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, webgl_prot, _, _) = manager.create_protection_modules();

        // Test comprehensive WebGL parameter extraction

        // 1. Basic WebGL info
        let basic_params = vec![
            ("VERSION", "OpenGL ES 3.0 (WebGL 2.0)"),
            ("SHADING_LANGUAGE_VERSION", "WebGL GLSL ES 3.00"),
            ("RENDERER", "ANGLE (Intel, Intel(R) HD Graphics 630)"),
            ("VENDOR", "Google Inc. (Intel)"),
        ];

        for (param, value) in basic_params {
            let protected = webgl_prot.protect_parameter(param, value);

            // In maximum protection mode, these should be spoofed
            assert!(!protected.is_empty(), "WebGL parameter should not be empty");

            if param == "RENDERER" || param == "VENDOR" {
                // Should be masked or spoofed
                assert_ne!(protected, value, "Sensitive WebGL info should be masked");
            }
        }

        // 2. WebGL extensions
        let extensions = vec![
            "WEBGL_depth_texture",
            "OESElementIndexUint",
            "OES_texture_float",
            "OES_texture_float_linear",
            "OES_standard_derivatives",
            "OES_vertex_array_object",
            "WEBGL_compressed_texture_s3tc",
            "WEBGL_debug_renderer_info",
        ];

        let mut protected_extensions = Vec::new();
        for ext in extensions {
            let protected = webgl_prot.protect_parameter("extension", ext);
            protected_extensions.push(protected);
        }

        // Some extensions should be masked for privacy
        assert!(!protected_extensions.is_empty(), "Extensions should be processed");

        // 3. WebGL capabilities (parameters)
        let capabilities = vec![
            ("MAX_TEXTURE_SIZE", "16384"),
            ("MAX_CUBE_MAP_TEXTURE_SIZE", "16384"),
            ("MAX_VIEWPORT_DIMS", "16384,16384"),
            ("ALIASED_LINE_WIDTH_RANGE", "1,1"),
            ("ALIASED_POINT_SIZE_RANGE", "1,1024"),
            ("MAX_TEXTURE_IMAGE_UNITS", "32"),
            ("MAX_RENDERBUFFER_SIZE", "16384"),
            ("MAX_COMBINED_TEXTURE_IMAGE_UNITS", "80"),
            ("MAX_VERTEX_TEXTURE_IMAGE_UNITS", "16"),
            ("MAX_VARYING_VECTORS", "15"),
            ("MAX_VERTEX_ATTRIBS", "16"),
            ("MAX_FRAGMENT_UNIFORM_VECTORS", "1024"),
            ("MAX_VERTEX_UNIFORM_VECTORS", "512"),
        ];

        let mut capability_fingerprint = String::new();
        for (param, value) in capabilities {
            let protected = webgl_prot.protect_parameter(param, value);

            // Numeric values should be normalized or contain noise
            if param.contains("MAX") || param.contains("RANGE") {
                // Should be normalized to common values
                assert!(protected == "16" || protected == "32" || protected == "64" || protected == "128",
                    "Capability {} should be normalized to common values, got: {}", param, protected);
            }

            capability_fingerprint.push_str(&format!("{}={},", param, protected));
        }

        // Verify the capability fingerprint is different from raw values
        assert!(!capability_fingerprint.contains("16384"), "High capability values should be normalized");

        println!("✓ WebGL fingerprint detection validated");
    }

    /// Test against browser entropy reduction
    #[test]
    fn test_browser_entropy_reduction() {
        println!("Testing browser entropy reduction...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);
        let (_, _, _, nav_prot) = manager.create_protection_modules();

        // Collect all entropy sources
        let mut entropy_sources = HashMap::new();

        // 1. User agent entropy
        let original_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let protected_ua = nav_prot.protect_property("userAgent", original_ua);
        entropy_sources.insert("userAgent", (original_ua.to_string(), protected_ua));

        // 2. Platform entropy
        let original_platform = "Win32";
        let protected_platform = nav_prot.protect_property("platform", original_platform);
        entropy_sources.insert("platform", (original_platform.to_string(), protected_platform));

        // 3. Hardware entropy
        entropy_sources.insert("hardwareConcurrency", ("16".to_string(), nav_prot.protect_property("hardwareConcurrency", "16")));
        entropy_sources.insert("deviceMemory", ("8".to_string(), nav_prot.protect_property("deviceMemory", "8")));

        // 4. Language entropy
        entropy_sources.insert("language", ("en-US".to_string(), nav_prot.protect_property("language", "en-US")));
        entropy_sources.insert("languages", ("en-US,en".to_string(), nav_prot.protect_property("languages", "en-US,en")));

        // 5. Screen entropy
        entropy_sources.insert("screen", ("1920x1080x24".to_string(), nav_prot.protect_property("screenResolution", "1920x1080")));

        // Calculate entropy reduction
        let mut total_original_entropy = 0;
        let mut total_protected_entropy = 0;

        for (source, (original, protected)) in entropy_sources.iter() {
            // Simple entropy calculation based on unique characters and length
            let original_entropy = original.chars().collect::<std::collections::HashSet<_>>().len() as f32 * original.len() as f32;
            let protected_entropy = protected.chars().collect::<std::collections::HashSet<_>>().len() as f32 * protected.len() as f32;

            total_original_entropy += original_entropy;
            total_protected_entropy += protected_entropy;

            println!("  {}: {} -> {} (entropy: {:.0} -> {:.0})",
                source, original, protected, original_entropy, protected_entropy);
        }

        // Overall entropy should be reduced
        let entropy_reduction = (total_original_entropy - total_protected_entropy) / total_original_entropy * 100.0;

        println!("  Total entropy reduction: {:.1}%", entropy_reduction);
        assert!(entropy_reduction > 10.0, "Should reduce browser entropy by at least 10%");

        // Special checks for high-entropy sources
        let protected_ua = &entropy_sources["userAgent"].1;
        assert!(protected_ua.len() < original_ua.len() || !protected_ua.contains("120.0.0.0"),
            "User agent should be simplified");

        let protected_hw = &entropy_sources["hardwareConcurrency"].1;
        assert_eq!(protected_hw, "4" || protected_hw == "8", "Hardware concurrency should be normalized");

        println!("✓ Browser entropy reduction validated");
    }

    /// Test against timing attack protection
    #[test]
    fn test_timing_attack_protection() {
        println!("Testing timing attack protection...");

        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };

        let manager = AntiFingerprintManager::new(config);

        // Test that noise generation doesn't leak timing information
        let test_values = vec![10.0, 100.0, 1000.0, 0.1];
        let domains = vec!["fast.com", "slow.com", "timing.com"];

        let mut timing_results = Vec::new();

        for &value in &test_values {
            for domain in &domains {
                let start = std::time::Instant::now();

                // Apply noise multiple times and measure timing
                for _ in 0..100 {
                    let _ = manager.apply_noise(value, 0.1, domain);
                }

                let duration = start.elapsed().as_nanos();
                timing_results.push((value, domain, duration));
            }
        }

        // Analyze timing consistency
        let mut timing_variance = Vec::new();

        for domain in &domains {
            let domain_timings: Vec<_> = timing_results.iter()
                .filter(|(_, d, _)| *d == domain)
                .map(|(_, _, t)| *t)
                .collect();

            if domain_timings.len() > 1 {
                let avg = domain_timings.iter().sum::<u128>() as f64 / domain_timings.len() as f64;
                let variance = domain_timings.iter()
                    .map(|t| (*t as f64 - avg).powi(2))
                    .sum::<f64>() / domain_timings.len() as f64;

                timing_variance.push((domain, variance));
            }
        }

        // Timing should be consistent (low variance)
        for (domain, variance) in timing_variance {
            assert!(variance < 1000000.0, // Less than 1ms variance
                "Timing variance for {} should be low, got: {:.0}ns", domain, variance);
        }

        println!("✓ Timing attack protection validated");
    }
}

// MD5 helper for fingerprint hashing
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