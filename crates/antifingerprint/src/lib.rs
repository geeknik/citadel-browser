//! Anti-fingerprinting protections for Citadel Browser
//!
//! This crate provides tools and middleware to defeat browser fingerprinting techniques
//! including those used by libraries like FingerprintJS.

mod canvas;
mod navigator;
mod webgl;
mod audio;
// These modules will be implemented later
// mod screen;
// mod fonts;
// mod timezone;
mod metrics;

use citadel_security::context::{SecurityContext, FingerprintProtection, FingerprintProtectionLevel};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use rand::{SeedableRng, Rng};
use rand::rngs::StdRng;
use rand_chacha::ChaCha20Rng;
use rand_distr::{Normal, Distribution};
use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use log::{debug, info, warn};
use metrics::{FingerprintMetrics, ProtectionType, DomainStats};

/// Errors that can occur during anti-fingerprinting operations
#[derive(Error, Debug)]
pub enum FingerprintError {
    #[error("Failed to initialize fingerprint protection: {0}")]
    InitializationError(String),
    
    #[error("Canvas operation error: {0}")]
    CanvasError(String),
    
    #[error("WebGL protection error: {0}")]
    WebGLError(String),
    
    #[error("Audio context protection error: {0}")]
    AudioError(String),
}

/// Core manager for anti-fingerprinting protections
#[derive(Debug, Clone)]
pub struct FingerprintManager {
    /// Reference to the security context
    security_context: SecurityContext,
    /// Session-specific fingerprint seed
    session_seed: u64,
    /// Whether this browser session should have consistent fingerprints
    consistent_within_session: bool,
}

impl FingerprintManager {
    /// Create a new fingerprint manager with the provided security context
    pub fn new(security_context: SecurityContext) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        Self {
            security_context,
            session_seed: rng.gen(),
            consistent_within_session: true,
        }
    }
    
    /// Get the current fingerprint protection configuration
    pub fn protection_config(&self) -> &FingerprintProtection {
        self.security_context.fingerprint_protection()
    }
    
    /// Set whether fingerprints should be consistent within a session
    pub fn set_consistent_within_session(&mut self, consistent: bool) {
        self.consistent_within_session = consistent;
    }
    
    /// Generate a domain-specific seed for deterministic randomization
    pub fn domain_seed(&self, domain: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        domain.hash(&mut hasher);
        self.session_seed.hash(&mut hasher);
        hasher.finish()
    }
    
    /// Apply a subtle random noise to a numeric value
    pub fn apply_noise<T>(&self, value: T, noise_factor: f64, domain: &str) -> T 
    where 
        T: Into<f64> + From<f64>
    {
        let value_f64 = value.into();
        let domain_seed = self.domain_seed(domain);
        
        // Use ChaCha20Rng which is cryptographically secure instead of StdRng
        let mut rng = if self.consistent_within_session {
            ChaCha20Rng::seed_from_u64(domain_seed)
        } else {
            ChaCha20Rng::from_entropy()
        };
        
        // Create a normal distribution centered on 0 with standard deviation based on noise factor
        let normal = Normal::new(0.0, noise_factor * value_f64.abs().max(0.001)).unwrap_or(Normal::new(0.0, 0.001).unwrap());
        
        // Get a random value from the distribution
        let noise = normal.sample(&mut rng);
        
        // Apply the noise to the original value
        T::from(value_f64 + noise)
    }
    
    /// Apply noise specifically for f32 values (working around From<f64> limitation)
    pub fn apply_noise_f32(&self, value: f32, noise_factor: f64, domain: &str) -> f32 {
        let value_f64 = value as f64;
        let result_f64 = self.apply_noise(value_f64, noise_factor, domain);
        result_f64 as f32
    }
}

/// Create a simple hash from user agent for use with fingerprinting normalization
pub fn user_agent_hash(user_agent: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    user_agent.hash(&mut hasher);
    hasher.finish()
}

/// Meta-data about the browser's fingerprint protection capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintProtectionInfo {
    /// The level of protection enabled
    pub level: String,
    /// Whether canvas fingerprinting protection is active
    pub canvas_protection: bool,
    /// Whether WebGL fingerprinting protection is active
    pub webgl_protection: bool,
    /// Whether audio fingerprinting protection is active
    pub audio_protection: bool,
    /// Whether font enumeration protection is active
    pub font_protection: bool,
}

impl FingerprintProtectionInfo {
    /// Create a new instance based on the current security context
    pub fn from_security_context(context: &SecurityContext) -> Self {
        let fp = context.fingerprint_protection();
        
        Self {
            level: format!("{:?}", fp.level),
            canvas_protection: fp.canvas_noise,
            webgl_protection: fp.spoof_webgl,
            audio_protection: fp.audio_noise,
            font_protection: fp.normalize_fonts,
        }
    }
}

/// Adds randomized noise to values to prevent fingerprinting
/// while maintaining usability
pub fn apply_noise<T>(value: T, noise_factor: f64) -> T
where
    T: Into<f64> + From<f64>,
{
    let value_f64: f64 = value.into();
    
    // Use cryptographically secure RNG
    let mut rng = ChaCha20Rng::from_entropy();
    
    // Ensure noise_factor is positive
    let noise_factor = noise_factor.abs().max(0.001);
    
    // Normal distribution with mean=0 and std_dev=noise_factor
    let normal = Normal::new(0.0, noise_factor).unwrap();
    let noise = normal.sample(&mut rng);
    
    // Apply noise to the value
    let result = value_f64 + noise;
    
    // Convert back to original type
    T::from(result)
}

/// Specialized version for f32 values to avoid type conversion issues
pub fn apply_noise_f32(value: f32, noise_factor: f32) -> f32 {
    let mut rng = ChaCha20Rng::from_entropy();
    let noise_factor = noise_factor.abs().max(0.001);
    
    let normal = Normal::new(0.0, noise_factor as f64).unwrap();
    let noise = normal.sample(&mut rng) as f32;
    
    value + noise
}

/// Anti-fingerprinting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiFingerprintConfig {
    /// Whether anti-fingerprinting is enabled
    pub enabled: bool,
    
    /// Level of protection (higher = more protection but potentially more breakage)
    pub protection_level: ProtectionLevel,
    
    /// Custom settings for specific features
    pub custom_settings: HashMap<String, bool>,
}

/// Level of protection against fingerprinting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionLevel {
    /// Basic protection that shouldn't break most sites
    Basic,
    
    /// Medium protection that may break some sites
    Medium,
    
    /// Maximum protection that may break many sites
    Maximum,
}

impl Default for AntiFingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protection_level: ProtectionLevel::Medium,
            custom_settings: HashMap::new(),
        }
    }
}

/// Manages anti-fingerprinting protections
#[derive(Debug, Clone)]
pub struct AntiFingerprintManager {
    config: AntiFingerprintConfig,
    /// Metrics for tracking fingerprinting attempts
    metrics: Arc<self::FingerprintMetrics>,
}

impl AntiFingerprintManager {
    /// Creates a new anti-fingerprinting manager with the given configuration
    pub fn new(config: AntiFingerprintConfig) -> Self {
        Self { 
            config,
            metrics: self::FingerprintMetrics::new(),
        }
    }
    
    /// Creates a new anti-fingerprinting manager with default configuration
    pub fn default() -> Self {
        Self {
            config: AntiFingerprintConfig::default(),
            metrics: self::FingerprintMetrics::new(),
        }
    }
    
    /// Returns the current configuration
    pub fn config(&self) -> &AntiFingerprintConfig {
        &self.config
    }
    
    /// Returns the metrics tracker
    pub fn metrics(&self) -> Arc<self::FingerprintMetrics> {
        self.metrics.clone()
    }
    
    /// Updates the configuration
    pub fn update_config(&mut self, config: AntiFingerprintConfig) {
        info!("Updating anti-fingerprinting configuration");
        self.config = config;
    }
    
    /// Records a blocked fingerprinting attempt
    pub fn record_blocked(&self, protection_type: self::ProtectionType, domain: &str) {
        self.metrics.record_blocked(protection_type, domain);
    }
    
    /// Records a normalized fingerprinting attempt
    pub fn record_normalized(&self, protection_type: self::ProtectionType, domain: &str) {
        self.metrics.record_normalized(protection_type, domain);
    }
    
    /// Determines if a feature should be protected based on configuration
    pub fn should_protect_feature(&self, feature_name: &str) -> bool {
        // Check if anti-fingerprinting is enabled at all
        if !self.config.enabled {
            return false;
        }
        
        // Check for custom setting
        if let Some(setting) = self.config.custom_settings.get(feature_name) {
            return *setting;
        }
        
        // Default based on protection level
        match self.config.protection_level {
            ProtectionLevel::Basic => {
                matches!(feature_name, "user_agent" | "platform" | "language")
            }
            ProtectionLevel::Medium => {
                // Medium protects most features except those that commonly break sites
                !matches!(feature_name, "webgl_vendor" | "timezone_precise")
            }
            ProtectionLevel::Maximum => true,
        }
    }
    
    /// Creates a complete set of protection modules with metrics tracking
    pub fn create_protection_modules(&self) -> (CanvasProtection, WebGLProtection, AudioProtection, NavigatorProtection) {
        let metrics = self.metrics();
        let sc = self.config.enabled;
        
        // Create security context for fingerprint manager
        let security_context = SecurityContext::new();
        let fp_manager = FingerprintManager::new(security_context);
        
        // Create all protection modules with metrics attached
        let canvas_protection = CanvasProtection::new(fp_manager.clone())
            .with_metrics(metrics.clone());
            
        let webgl_protection = WebGLProtection::new(fp_manager.clone())
            .with_metrics(metrics.clone());
            
        let audio_protection = AudioProtection::new(fp_manager.clone())
            .with_metrics(metrics.clone());
            
        let mut navigator_protection = NavigatorProtection::new(fp_manager);
        
        (canvas_protection, webgl_protection, audio_protection, navigator_protection)
    }
    
    /// Get statistics about fingerprinting attempts
    pub fn get_fingerprinting_statistics(&self) -> Vec<(String, usize)> {
        self.metrics.top_fingerprinting_domains(10)
    }
    
    /// Get detailed domain statistics
    pub fn get_domain_statistics(&self, domain: &str) -> Option<DomainStats> {
        self.metrics.domain_statistics(domain)
    }
    
    /// Reset all fingerprinting metrics
    pub fn reset_metrics(&self) {
        self.metrics.reset();
    }
    
    /// Export metrics for display in the browser UI
    pub fn export_metrics_summary(&self) -> FingerprintMetricsSummary {
        FingerprintMetricsSummary {
            total_attempts: self.metrics.total_attempts(),
            blocked_attempts: self.metrics.blocked_attempts.load(std::sync::atomic::Ordering::Relaxed),
            normalized_attempts: self.metrics.normalized_attempts.load(std::sync::atomic::Ordering::Relaxed),
            canvas_protections: self.metrics.protection_count(ProtectionType::Canvas),
            webgl_protections: self.metrics.protection_count(ProtectionType::WebGL),
            audio_protections: self.metrics.protection_count(ProtectionType::Audio),
            navigator_protections: self.metrics.protection_count(ProtectionType::Navigator),
            top_domains: self.metrics.top_fingerprinting_domains(5),
            since_first_attempt: self.metrics.time_since_first_attempt().map(|d| d.as_secs()),
        }
    }
}

/// Summary of fingerprinting metrics for UI display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintMetricsSummary {
    /// Total fingerprinting attempts
    pub total_attempts: usize,
    /// Completely blocked attempts
    pub blocked_attempts: usize,
    /// Normalized (modified) attempts
    pub normalized_attempts: usize,
    /// Canvas-related protections
    pub canvas_protections: usize,
    /// WebGL-related protections
    pub webgl_protections: usize,
    /// Audio-related protections
    pub audio_protections: usize,
    /// Navigator/platform protections
    pub navigator_protections: usize,
    /// Top domains attempting fingerprinting
    pub top_domains: Vec<(String, usize)>,
    /// Seconds since first fingerprinting attempt
    pub since_first_attempt: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_apply_noise() {
        // Test basic noise application
        let original: f32 = 100.0;
        let noise_factor: f32 = 5.0;
        
        // Apply noise multiple times and check that results vary
        let results: Vec<f32> = (0..10)
            .map(|_| apply_noise_f32(original, noise_factor))
            .collect();
        
        // Values should be different (with very high probability)
        let mut unique_values = 0;
        let mut seen_values = Vec::new();
        
        for &value in &results {
            // Check if this exact value has been seen before
            let mut is_new = true;
            for &seen in &seen_values {
                if (seen as f32 - value as f32).abs() < std::f32::EPSILON {
                    is_new = false;
                    break;
                }
            }
            
            if is_new {
                seen_values.push(value);
                unique_values += 1;
            }
        }
        
        // With enough noise, we should get multiple unique values
        assert!(unique_values > 1);
        
        // Values should be roughly within range
        for value in results {
            assert!((value - original).abs() < noise_factor * 3.0);
        }
    }
    
    #[test]
    fn test_protection_levels() {
        let basic_config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Basic,
            custom_settings: HashMap::new(),
        };
        
        let max_config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Maximum,
            custom_settings: HashMap::new(),
        };
        
        let basic_manager = AntiFingerprintManager::new(basic_config);
        let max_manager = AntiFingerprintManager::new(max_config);
        
        // Basic should protect user_agent but not screen_resolution
        assert!(basic_manager.should_protect_feature("user_agent"));
        assert!(!basic_manager.should_protect_feature("screen_resolution"));
        
        // Maximum should protect everything
        assert!(max_manager.should_protect_feature("user_agent"));
        assert!(max_manager.should_protect_feature("screen_resolution"));
    }
    
    #[test]
    fn test_custom_settings() {
        let mut custom_settings = HashMap::new();
        custom_settings.insert("screen_resolution".to_string(), true);
        
        let config = AntiFingerprintConfig {
            enabled: true,
            protection_level: ProtectionLevel::Basic, // Would normally not protect screen_resolution
            custom_settings,
        };
        
        let manager = AntiFingerprintManager::new(config);
        
        // Custom setting overrides the protection level
        assert!(manager.should_protect_feature("screen_resolution"));
    }
}

// Re-export important types from modules
pub use audio::{AudioProtection, AudioParamValues};
pub use canvas::CanvasProtection;
pub use webgl::{WebGLProtection, WebGLInfo, WebGLParameter};
pub use navigator::{NavigatorProtection, NavigatorInfo}; 