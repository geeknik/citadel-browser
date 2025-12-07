//! Hardware fingerprinting protection for Citadel Browser
//!
//! This module protects against hardware-based fingerprinting by normalizing
//! and randomizing hardware-related properties such as CPU cores, memory,
//! GPU information, and other hardware characteristics.

use std::collections::HashMap;
use rand::{Rng, SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;
use log::{debug, info};

/// Hardware fingerprinting protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProtectionConfig {
    /// Whether to normalize CPU information
    pub normalize_cpu: bool,
    /// Whether to normalize memory information
    pub normalize_memory: bool,
    /// Whether to normalize GPU information
    pub normalize_gpu: bool,
    /// Whether to normalize display information
    pub normalize_display: bool,
    /// Whether to add noise to hardware metrics
    pub add_metrics_noise: bool,
    /// Level of protection (0.0 to 1.0)
    pub protection_level: f32,
    /// Whether to use consistent hardware profile across sessions
    pub consistent_across_sessions: bool,
}

impl Default for HardwareProtectionConfig {
    fn default() -> Self {
        Self {
            normalize_cpu: true,
            normalize_memory: true,
            normalize_gpu: true,
            normalize_display: true,
            add_metrics_noise: true,
            protection_level: 0.8,
            consistent_across_sessions: false,
        }
    }
}

/// Protected hardware information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedHardwareInfo {
    /// CPU core count (normalized)
    pub cpu_cores: u8,
    /// Hardware concurrency (normalized)
    pub hardware_concurrency: u8,
    /// Device memory in GB (normalized)
    pub device_memory: f32,
    /// Total memory in bytes (normalized)
    pub total_memory: u64,
    /// GPU vendor (normalized)
    pub gpu_vendor: String,
    /// GPU renderer (normalized)
    pub gpu_renderer: String,
    /// Screen width (normalized)
    pub screen_width: u32,
    /// Screen height (normalized)
    pub screen_height: u32,
    /// Color depth (normalized)
    pub color_depth: u8,
    /// Pixel depth (normalized)
    pub pixel_depth: u8,
}

/// Hardware fingerprinting protection manager
#[derive(Debug)]
pub struct HardwareProtection {
    config: HardwareProtectionConfig,
    /// Session-specific random seed
    session_seed: u64,
    /// Cache of protected hardware info
    hardware_cache: Arc<RwLock<HashMap<String, ProtectedHardwareInfo>>>,
    /// Base hardware profile for consistent generation
    base_profile: ProtectedHardwareInfo,
}

impl HardwareProtection {
    /// Create a new hardware protection instance
    pub fn new(config: HardwareProtectionConfig) -> Self {
        let session_seed = if config.consistent_across_sessions {
            // Use a fixed seed for consistency
            0xB5B5B5B5B5B5B5B5
        } else {
            // Generate a random seed for this session
            rand::thread_rng().gen()
        };

        let base_profile = Self::generate_base_profile();

        Self {
            config,
            session_seed,
            hardware_cache: Arc::new(RwLock::new(HashMap::new())),
            base_profile,
        }
    }

    /// Generate a base hardware profile
    fn generate_base_profile() -> ProtectedHardwareInfo {
        ProtectedHardwareInfo {
            cpu_cores: 4, // Common value
            hardware_concurrency: 4,
            device_memory: 8.0, // 8GB
            total_memory: 8 * 1024 * 1024 * 1024, // 8GB
            gpu_vendor: "Generic".to_string(),
            gpu_renderer: "Generic Graphics".to_string(),
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            pixel_depth: 24,
        }
    }

    /// Get protected hardware information for a specific domain
    pub fn get_protected_hardware_info(&self, domain: &str) -> ProtectedHardwareInfo {
        let cache_key = domain.to_string();

        // Check cache first
        {
            let cache = self.hardware_cache.read();
            if let Some(info) = cache.get(&cache_key) {
                return info.clone();
            }
        }

        // Generate new protected hardware info
        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        let mut info = self.base_profile.clone();

        if self.config.normalize_cpu {
            // Normalize to common values with some variation
            let common_cores = vec![2, 4, 8];
            info.cpu_cores = *common_cores.choose(&mut rng).unwrap_or(&4);
            info.hardware_concurrency = info.cpu_cores;

            // Add slight variation based on protection level
            if self.config.add_metrics_noise && self.config.protection_level > 0.5 {
                if rng.gen_bool(0.2) {
                    info.hardware_concurrency = (info.hardware_concurrency as i32 + rng.gen_range(-1..=1)).max(1) as u8;
                }
            }
        }

        if self.config.normalize_memory {
            // Normalize to common memory sizes
            let common_memory = vec![4.0, 8.0, 16.0];
            info.device_memory = *common_memory.choose(&mut rng).unwrap_or(&8.0);
            info.total_memory = (info.device_memory * 1024.0 * 1024.0 * 1024.0) as u64;
        }

        if self.config.normalize_gpu {
            let gpu_vendors = vec![
                "Google Inc. (Intel)",
                "Google Inc. (NVIDIA)",
                "Google Inc. (AMD)",
                "Mozilla",
            ];
            info.gpu_vendor = gpu_vendors.choose(&mut rng).unwrap_or(&"Mozilla").to_string();

            let gpu_renderers = vec![
                "ANGLE (Intel, Intel(R) HD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
                "ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 6GB Direct3D11 vs_5_0 ps_5_0, D3D11)",
                "ANGLE (AMD, AMD Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0, D3D11)",
                "WebKit WebGL",
                "Mesa DRI Intel(R) UHD Graphics 620 (WHL GT2)",
            ];
            info.gpu_renderer = gpu_renderers.choose(&mut rng).unwrap_or(&"WebKit WebGL").to_string();
        }

        if self.config.normalize_display {
            // Normalize to common resolutions
            let common_resolutions = vec![
                (1366, 768),
                (1920, 1080),
                (1440, 900),
                (1536, 864),
                (2560, 1440),
            ];
            (info.screen_width, info.screen_height) = *common_resolutions.choose(&mut rng).unwrap_or(&(1920, 1080));

            info.color_depth = 24;
            info.pixel_depth = 24;

            // Add slight noise to dimensions
            if self.config.add_metrics_noise && self.config.protection_level > 0.6 {
                let width_noise = rng.gen_range(-10..=10);
                let height_noise = rng.gen_range(-10..=10);
                info.screen_width = (info.screen_width as i32 + width_noise).max(1024) as u32;
                info.screen_height = (info.screen_height as i32 + height_noise).max(768) as u32;
            }
        }

        // Cache the result
        {
            let mut cache = self.hardware_cache.write();
            cache.insert(cache_key, info.clone());
        }

        info
    }

    /// Get protected CPU cores count
    pub fn get_cpu_cores(&self, domain: &str) -> u8 {
        self.get_protected_hardware_info(domain).cpu_cores
    }

    /// Get protected hardware concurrency
    pub fn get_hardware_concurrency(&self, domain: &str) -> u8 {
        self.get_protected_hardware_info(domain).hardware_concurrency
    }

    /// Get protected device memory
    pub fn get_device_memory(&self, domain: &str) -> f32 {
        self.get_protected_hardware_info(domain).device_memory
    }

    /// Get protected GPU information
    pub fn get_gpu_info(&self, domain: &str) -> (String, String) {
        let info = self.get_protected_hardware_info(domain);
        (info.gpu_vendor, info.gpu_renderer)
    }

    /// Get protected screen information
    pub fn get_screen_info(&self, domain: &str) -> (u32, u32, u8, u8) {
        let info = self.get_protected_hardware_info(domain);
        (
            info.screen_width,
            info.screen_height,
            info.color_depth,
            info.pixel_depth,
        )
    }

    /// Add noise to a hardware metric
    pub fn add_hardware_noise(&self, value: u64, domain: &str, metric_type: &str) -> u64 {
        if !self.config.add_metrics_noise {
            return value;
        }

        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(
            self.session_seed ^ domain_seed ^ Self::metric_seed(metric_type)
        );

        let noise_factor = self.config.protection_level * 0.1; // Max 10% noise
        let noise = (rng.gen_range(-1.0f32..=1.0f32) * noise_factor * value as f32) as i64;

        (value as i64 + noise).max(1) as u64
    }

    /// Get protected battery information
    pub fn get_battery_info(&self, domain: &str) -> Option<(f32, bool)> {
        let _info = self.get_protected_hardware_info(domain);
        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        if self.config.protection_level > 0.7 {
            // High protection: either hide battery info completely or return generic values
            if rng.gen_bool(0.5) {
                None
            } else {
                Some((0.8, true)) // Generic battery info
            }
        } else {
            // Lower protection: normalize battery level
            let normalized_level = (rng.gen_range(0.2f32..=1.0f32) * 100.0f32).round() / 100.0f32;
            Some((normalized_level, true))
        }
    }

    /// Get protected connection information
    pub fn get_connection_info(&self, domain: &str) -> HashMap<String, String> {
        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        let mut info = HashMap::new();

        if self.config.protection_level > 0.5 {
            // Normalize connection type
            let connection_types = vec![
                "4g", "wifi", "ethernet", "bluetooth", "cellular", "unknown"
            ];
            let conn_type = connection_types.choose(&mut rng).unwrap_or(&"unknown");
            info.insert("effectiveType".to_string(), conn_type.to_string());
            info.insert("type".to_string(), conn_type.to_string());

            // Add reasonable but normalized values
            info.insert("downlink".to_string(), format!("{:.1}", rng.gen_range(1.0..=50.0)));
            info.insert("rtt".to_string(), format!("{}", rng.gen_range(50..=300)));
            info.insert("saveData".to_string(), (rng.gen_bool(0.2)).to_string());
        } else {
            // More permissive - expose actual connection but with some normalization
            info.insert("effectiveType".to_string(), "4g".to_string());
            info.insert("type".to_string(), "cellular".to_string());
            info.insert("downlink".to_string(), "10.0".to_string());
            info.insert("rtt".to_string(), "100".to_string());
            info.insert("saveData".to_string(), "false".to_string());
        }

        info
    }

    /// Generate domain-specific seed
    fn domain_seed(&self, domain: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        domain.hash(&mut hasher);
        hasher.finish()
    }

    /// Generate metric-specific seed
    fn metric_seed(metric_type: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        metric_type.hash(&mut hasher);
        hasher.finish()
    }

    /// Reset hardware cache
    pub fn reset_cache(&self) {
        self.hardware_cache.write().clear();
        info!("Hardware protection cache reset");
    }

    /// Get current configuration
    pub fn config(&self) -> &HardwareProtectionConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: HardwareProtectionConfig) {
        self.config = config;
        self.reset_cache();
        info!("Hardware protection configuration updated");
    }
}

impl Clone for HardwareProtection {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            session_seed: self.session_seed,
            hardware_cache: Arc::new(RwLock::new(self.hardware_cache.read().clone())),
            base_profile: self.base_profile.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_normalization() {
        let config = HardwareProtectionConfig::default();
        let protection = HardwareProtection::new(config);

        let info = protection.get_protected_hardware_info("example.com");

        // CPU should be normalized to common values
        assert!(info.cpu_cores == 2 || info.cpu_cores == 4 || info.cpu_cores == 8);

        // Memory should be normalized to common values
        assert!(info.device_memory == 4.0 || info.device_memory == 8.0 || info.device_memory == 16.0);

        // Resolution should be common
        assert!(info.screen_width >= 1366 && info.screen_width <= 2560);
        assert!(info.screen_height >= 768 && info.screen_height <= 1440);
    }

    #[test]
    fn test_domain_consistency() {
        let config = HardwareProtectionConfig::default();
        let protection = HardwareProtection::new(config);

        let info1 = protection.get_protected_hardware_info("example.com");
        let info2 = protection.get_protected_hardware_info("example.com");
        let info3 = protection.get_protected_hardware_info("different.com");

        // Same domain should get same info
        assert_eq!(info1, info2);

        // Different domains should get different info
        assert!(info1 != info3);
    }

    #[test]
    fn test_hardware_noise() {
        let mut config = HardwareProtectionConfig::default();
        config.add_metrics_noise = true;
        config.protection_level = 1.0;

        let protection = HardwareProtection::new(config);
        let original_value = 1000u64;

        let values: Vec<u64> = (0..10)
            .map(|_| protection.add_hardware_noise(original_value, "example.com", "test"))
            .collect();

        // Values should vary but remain reasonable
        for &value in &values {
            assert!(value > 0);
            let diff = (value as i64 - original_value as i64).abs() as u64;
            assert!(diff < original_value / 5); // Within 20%
        }

        // Should have different values
        let unique_values: HashSet<u64> = values.iter().cloned().collect();
        assert!(unique_values.len() > 1);
    }

    #[test]
    fn test_battery_protection() {
        let config = HardwareProtectionConfig::default();
        let protection = HardwareProtection::new(config);

        let battery_info = protection.get_battery_info("example.com");

        // Should either be None or have reasonable values
        if let Some((level, charging)) = battery_info {
            assert!(level >= 0.0 && level <= 1.0);
            assert!(charging == true || charging == false);
        }
    }

    #[test]
    fn test_connection_info() {
        let config = HardwareProtectionConfig::default();
        let protection = HardwareProtection::new(config);

        let info = protection.get_connection_info("example.com");

        assert!(info.contains_key("effectiveType"));
        assert!(info.contains_key("type"));
        assert!(info.contains_key("downlink"));
        assert!(info.contains_key("rtt"));

        // Check reasonable values
        if let Some(downlink) = info.get("downlink") {
            assert!(downlink.parse::<f32>().is_ok());
        }

        if let Some(rtt) = info.get("rtt") {
            assert!(rtt.parse::<u32>().is_ok());
        }
    }

    #[test]
    fn test_consistent_across_sessions() {
        let mut config = HardwareProtectionConfig::default();
        config.consistent_across_sessions = true;

        let protection1 = HardwareProtection::new(config.clone());
        let protection2 = HardwareProtection::new(config);

        let info1 = protection1.get_protected_hardware_info("example.com");
        let info2 = protection2.get_protected_hardware_info("example.com");

        // Should be identical when consistent across sessions is enabled
        assert_eq!(info1, info2);
    }
}