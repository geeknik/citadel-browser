//! Font fingerprinting protection for Citadel Browser
//!
//! This module provides protection against font-based fingerprinting attacks
//! by normalizing font enumeration and introducing carefully controlled noise.

use std::collections::HashSet;
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;
use log::{debug, info};

/// Font fingerprinting protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontProtectionConfig {
    /// Whether to normalize font enumeration
    pub normalize_fonts: bool,
    /// Whether to add noise to font metrics
    pub add_metrics_noise: bool,
    /// Level of protection (0.0 to 1.0)
    pub protection_level: f32,
    /// Maximum number of fonts to expose
    pub max_font_count: usize,
    /// Whether to use consistent font list across sessions
    pub consistent_across_sessions: bool,
}

impl Default for FontProtectionConfig {
    fn default() -> Self {
        Self {
            normalize_fonts: true,
            add_metrics_noise: true,
            protection_level: 0.7,
            max_font_count: 50,
            consistent_across_sessions: false,
        }
    }
}

/// Font information with protected metrics
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtectedFontInfo {
    /// Font family name (normalized)
    pub family: String,
    /// Whether the font is serif
    pub serif: bool,
    /// Whether the font is monospace
    pub monospace: bool,
    /// Protected font size
    pub size: u16,
    /// Protected weight
    pub weight: u16,
}

/// Font fingerprinting protection manager
#[derive(Debug)]
pub struct FontProtection {
    config: FontProtectionConfig,
    /// Session-specific random seed
    session_seed: u64,
    /// Cache of protected font sets
    font_cache: Arc<RwLock<HashSet<ProtectedFontInfo>>>,
    /// Common fonts that are safe to expose
    common_fonts: Vec<String>,
}

impl FontProtection {
    /// Create a new font protection instance
    pub fn new(config: FontProtectionConfig) -> Self {
        let session_seed = if config.consistent_across_sessions {
            // Use a fixed seed for consistency
            0x5A5A5A5A5A5A5A5A
        } else {
            // Generate a random seed for this session
            rand::thread_rng().gen()
        };

        let common_fonts = vec![
            "Arial".to_string(),
            "Arial Black".to_string(),
            "Comic Sans MS".to_string(),
            "Courier".to_string(),
            "Courier New".to_string(),
            "Georgia".to_string(),
            "Helvetica".to_string(),
            "Impact".to_string(),
            "Times".to_string(),
            "Times New Roman".to_string(),
            "Trebuchet MS".to_string(),
            "Verdana".to_string(),
            "serif".to_string(),
            "sans-serif".to_string(),
            "monospace".to_string(),
            "cursive".to_string(),
            "fantasy".to_string(),
        ];

        Self {
            config,
            session_seed,
            font_cache: Arc::new(RwLock::new(HashSet::new())),
            common_fonts,
        }
    }

    /// Normalize a font name to prevent fingerprinting
    pub fn normalize_font_name(&self, font_name: &str) -> String {
        if !self.config.normalize_fonts {
            return font_name.to_string();
        }

        // Convert to lowercase and trim whitespace
        let normalized = font_name.trim().to_lowercase();

        // Map common variations to standard names
        match normalized.as_str() {
            "arial" | "helvetica" | "sans-serif" => "sans-serif".to_string(),
            "times" | "times new roman" | "georgia" | "serif" => "serif".to_string(),
            "courier" | "courier new" | "monaco" | "monospace" => "monospace".to_string(),
            "comic sans" | "comic sans ms" | "cursive" => "cursive".to_string(),
            "impact" | "fantasy" => "fantasy".to_string(),
            _ => {
                // For unknown fonts, check if they're in our common list
                if self.common_fonts.iter().any(|f| f.to_lowercase() == normalized) {
                    font_name.trim().to_string()
                } else {
                    // Return a generic font family or hide entirely
                    if self.config.protection_level > 0.5 {
                        "sans-serif".to_string()
                    } else {
                        // Slightly less aggressive - return truncated name
                        normalized.chars().take(10).collect::<String>()
                    }
                }
            }
        }
    }

    /// Add noise to font metrics to prevent fingerprinting
    pub fn add_metrics_noise(&self, value: f32) -> f32 {
        if !self.config.add_metrics_noise {
            return value;
        }

        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed + value as u64);
        let noise_factor = self.config.protection_level * 0.05; // Max 5% noise
        let noise = rng.gen_range(-noise_factor..=noise_factor) * value;

        (value + noise).max(0.1) // Ensure minimum value
    }

    /// Get a protected list of available fonts
    pub fn get_protected_font_list(&self, domain: &str) -> Vec<String> {
        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        let cache = self.font_cache.read();

        // Return cached fonts if available
        if !cache.is_empty() {
            return cache.iter()
                .map(|f| f.family.clone())
                            .collect::<Vec<String>>();
        }

        // Generate a consistent font list
        let mut font_list = self.common_fonts.clone();

        // Shuffle based on domain for uniqueness
        font_list.shuffle(&mut rng);

        // Limit number of fonts
        font_list.truncate(self.config.max_font_count);

        // Occasionally add/remove fonts based on protection level
        if self.config.protection_level > 0.8 && rng.gen_bool(0.3) {
            // Occasionally add a dummy font
            font_list.push(format!("Font_{}", rng.gen_range(100..999)));
        }

        drop(cache);

        // Update cache
        let protected_fonts: HashSet<ProtectedFontInfo> = font_list.iter().map(|font| {
            ProtectedFontInfo {
                family: font.clone(),
                serif: font.to_lowercase().contains("serif") || font == "serif",
                monospace: font.to_lowercase().contains("mono") || font == "monospace",
                size: self.add_metrics_noise(16.0) as u16,
                weight: self.add_metrics_noise(400.0) as u16,
            }
        }).collect();

        *self.font_cache.write() = protected_fonts;

        font_list
    }

    /// Check if a font should be exposed to scripts
    pub fn should_expose_font(&self, font_name: &str) -> bool {
        if !self.config.normalize_fonts {
            return true;
        }

        let normalized = font_name.trim().to_lowercase();

        // Always expose generic font families
        match normalized.as_str() {
            "serif" | "sans-serif" | "monospace" | "cursive" | "fantasy" => return true,
            _ => {}
        }

        // Check if it's in our common font list
        self.common_fonts.iter().any(|f| {
            f.to_lowercase() == normalized ||
            f.to_lowercase().contains(&normalized) ||
            normalized.contains(&f.to_lowercase())
        })
    }

    /// Generate domain-specific seed
    fn domain_seed(&self, domain: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        domain.hash(&mut hasher);
        hasher.finish()
    }

    /// Get protected font metrics
    pub fn get_protected_metrics(&self, font_name: &str, original_width: u32, original_height: u32) -> (u32, u32) {
        if !self.config.add_metrics_noise {
            return (original_width, original_height);
        }

        let mut rng = ChaCha20Rng::seed_from_u64(
            self.session_seed ^
            self.domain_seed(font_name) ^
            ((original_width as u64) << 32 | original_height as u64)
        );

        let noise_factor = self.config.protection_level * 0.02; // Max 2% noise
        let width_noise = (rng.gen_range(-1.0..=1.0) * noise_factor * original_width as f32) as i32;
        let height_noise = (rng.gen_range(-1.0..=1.0) * noise_factor * original_height as f32) as i32;

        (
            (original_width as i32 + width_noise).max(1) as u32,
            (original_height as i32 + height_noise).max(1) as u32,
        )
    }

    /// Simulate font loading timing to prevent timing attacks
    pub fn get_font_load_delay(&self, font_name: &str, is_cached: bool) -> std::time::Duration {
        let base_delay = if is_cached {
            std::time::Duration::from_millis(5)
        } else {
            std::time::Duration::from_millis(50)
        };

        if self.config.protection_level < 0.5 {
            return base_delay;
        }

        // Add randomness based on font and domain
        let mut rng = ChaCha20Rng::seed_from_u64(
            self.session_seed ^ self.domain_seed(font_name)
        );

        let extra_delay = rng.gen_range(0..=20); // 0-20ms extra delay
        base_delay + std::time::Duration::from_millis(extra_delay)
    }

    /// Reset font cache (for testing or when context changes)
    pub fn reset_cache(&self) {
        self.font_cache.write().clear();
        info!("Font protection cache reset");
    }

    /// Get current configuration
    pub fn config(&self) -> &FontProtectionConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: FontProtectionConfig) {
        self.config = config;
        self.reset_cache();
        info!("Font protection configuration updated");
    }
}

impl Clone for FontProtection {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            session_seed: self.session_seed,
            font_cache: Arc::new(RwLock::new(self.font_cache.read().clone())),
            common_fonts: self.common_fonts.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_font_normalization() {
        let config = FontProtectionConfig::default();
        let protection = FontProtection::new(config);

        // Test basic normalization
        assert_eq!(protection.normalize_font_name("Arial"), "sans-serif");
        assert_eq!(protection.normalize_font_name("Times New Roman"), "serif");
        assert_eq!(protection.normalize_font_name("Courier New"), "monospace");

        // Test case insensitivity
        assert_eq!(protection.normalize_font_name("ARIAL"), "sans-serif");
        assert_eq!(protection.normalize_font_name("times new roman"), "serif");
    }

    #[test]
    fn test_metrics_noise() {
        let mut config = FontProtectionConfig::default();
        config.add_metrics_noise = true;
        config.protection_level = 1.0;

        let protection = FontProtection::new(config);
        let original_value = 100.0;

        // Apply noise multiple times
        let values: Vec<f32> = (0..10)
            .map(|_| protection.add_metrics_noise(original_value))
            .collect();

        // Values should vary but remain reasonable
        for &value in &values {
            assert!(value > 0.0);
            assert!((value - original_value).abs() < original_value * 0.1); // Within 10%
        }

        // Check that we get different values
        let unique_values: HashSet<f32> = values.iter().cloned().collect();
        assert!(unique_values.len() > 1);
    }

    #[test]
    fn test_font_list_generation() {
        let config = FontProtectionConfig::default();
        let protection = FontProtection::new(config);

        let font_list1 = protection.get_protected_font_list("example.com");
        let font_list2 = protection.get_protected_font_list("example.com");
        let font_list3 = protection.get_protected_font_list("different.com");

        // Same domain should get same list
        assert_eq!(font_list1, font_list2);

        // Different domains should get different lists (due to shuffling)
        // This might occasionally fail due to random chance
        if font_list1 == font_list3 {
            // Retry once more to confirm
            let font_list4 = protection.get_protected_font_list("another.com");
            assert!(font_list1 != font_list4 || font_list3 != font_list4);
        }

        // Should not exceed maximum font count
        assert!(font_list1.len() <= config.max_font_count);
    }

    #[test]
    fn test_font_exposure() {
        let config = FontProtectionConfig::default();
        let protection = FontProtection::new(config);

        // Generic fonts should always be exposed
        assert!(protection.should_expose_font("serif"));
        assert!(protection.should_expose_font("sans-serif"));
        assert!(protection.should_expose_font("monospace"));

        // Common fonts should be exposed
        assert!(protection.should_expose_font("Arial"));
        assert!(protection.should_expose_font("Times New Roman"));

        // Unknown fonts should be normalized or hidden
        assert!(!protection.should_expose_font("MyCustomFont123"));
    }

    #[test]
    fn test_protection_levels() {
        let mut config = FontProtectionConfig::default();

        // Low protection
        config.protection_level = 0.2;
        let protection_low = FontProtection::new(config);

        // High protection
        config.protection_level = 0.9;
        let protection_high = FontProtection::new(config);

        let test_font = "UnknownFont";
        let normalized_low = protection_low.normalize_font_name(test_font);
        let normalized_high = protection_high.normalize_font_name(test_font);

        // High protection should be more aggressive
        assert_eq!(normalized_high, "sans-serif");
        // Low protection should return truncated name
        assert!(normalized_low.len() <= 10);
    }
}