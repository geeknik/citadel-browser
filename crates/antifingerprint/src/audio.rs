//! Audio fingerprinting protection
//!
//! AudioContext fingerprinting is a powerful technique used by libraries like FingerprintJS.
//! This module implements protections against audio-based fingerprinting by adding
//! subtle noise to audio operations.

use crate::{FingerprintManager, FingerprintError, metrics::ProtectionType};
use std::sync::Arc;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Audio fingerprinting protection implementation
#[derive(Debug)]
pub struct AudioProtection {
    /// Reference to the fingerprint manager
    manager: FingerprintManager,
    /// Whether audio protection is enabled
    enabled: bool,
    /// Noise amplitude factor (0.0-1.0)
    noise_factor: f32,
    /// Optional metrics tracker
    metrics: Option<Arc<crate::metrics::FingerprintMetrics>>,
}

impl AudioProtection {
    /// Create a new audio protection instance
    pub fn new(manager: FingerprintManager) -> Self {
        let enabled = manager.protection_config().audio_noise;
        
        Self {
            manager,
            enabled,
            noise_factor: 0.0001, // Very subtle noise by default
            metrics: None,
        }
    }
    
    /// Create a new audio protection instance with custom noise factor
    pub fn with_noise_factor(manager: FingerprintManager, noise_factor: f32) -> Self {
        let mut protection = Self::new(manager);
        protection.noise_factor = noise_factor.clamp(0.0, 1.0);
        protection
    }
    
    /// Attach metrics tracking to this protection
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::FingerprintMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
    
    /// Record a protection event
    fn record_protection(&self, domain: &str, is_blocked: bool) {
        if let Some(metrics) = &self.metrics {
            if is_blocked {
                metrics.record_blocked(ProtectionType::Audio, domain);
            } else {
                metrics.record_normalized(ProtectionType::Audio, domain);
            }
        }
    }
    
    /// Apply noise to audio buffer data
    pub fn protect_audio_buffer(&self, buffer: &mut [f32], domain: &str) -> Result<(), FingerprintError> {
        if !self.enabled {
            return Ok(());
        }
        
        // Record this protection event
        self.record_protection(domain, false);
        
        // Add very subtle noise to audio samples
        for sample in buffer.iter_mut() {
            *sample = self.manager.apply_noise_f32(*sample, self.noise_factor as f64, domain);
        }
        
        Ok(())
    }
    
    /// Normalize frequency data to prevent analyzer-based fingerprinting
    pub fn protect_frequency_data(&self, data: &mut [u8], domain: &str) -> Result<(), FingerprintError> {
        if !self.enabled {
            return Ok(());
        }
        
        // Record this protection event
        self.record_protection(domain, false);
        
        // Add slight noise to frequency data
        let domain_seed = self.manager.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(domain_seed);

        for value in data.iter_mut() {
            // Use 50% chance of making small adjustment to ensure noise is detectable
            if rng.gen::<f32>() < 0.5 {
                let adjustment = if rng.gen::<bool>() { 1 } else { -1 };
                *value = (*value as i16 + adjustment).clamp(0, 255) as u8;
            }
        }
        
        Ok(())
    }
    
    /// Get normalized audio parameter values
    pub fn normalize_audio_params(&self, origin: &str) -> AudioParamValues {
        if !self.enabled {
            return AudioParamValues::default();
        }
        
        // Record this protection event
        self.record_protection(origin, false);
        
        // Calculate a deterministic seed for the domain
        let _domain_seed = self.manager.domain_seed(origin);
        
        // Create deterministic but non-unique audio params
        AudioParamValues {
            sample_rate: 44100.0, // Standard sample rate
            channel_count: 2,     // Standard stereo
            buffer_size: 1024,    // Common power-of-two buffer size
            time_constant: 0.8,   // Common analyzer time constant
            max_channel_count: 2, // Limit reported channels to 2
        }
    }
    
    /// Check if this domain should use WebAudio API mocking
    pub fn should_mock_audio_api(&self, domain: &str) -> bool {
        if !self.enabled {
            return false;
        }
        
        // Record this as a blocked (not just normalized) attempt
        self.record_protection(domain, true);
        
        // Determine if we should completely mock audio for this domain
        // based on domain reputation or other factors
        let domain_lower = domain.to_lowercase();
        
        // Check for known fingerprinting domains
        domain_lower.contains("fingerprint") || 
        domain_lower.contains("amplitude") || 
        domain_lower.contains("analytics")
    }
}

/// Standard WebAudio API parameters
#[derive(Debug, Clone, Copy)]
pub struct AudioParamValues {
    /// Sample rate in Hz
    pub sample_rate: f32,
    /// Channel count
    pub channel_count: u32,
    /// Audio buffer size
    pub buffer_size: u32,
    /// Analyzer time constant
    pub time_constant: f32,
    /// Maximum channel count reported
    pub max_channel_count: u32,
}

impl Default for AudioParamValues {
    fn default() -> Self {
        Self {
            sample_rate: 44100.0, // Most common sample rate
            channel_count: 2,     // Standard stereo
            buffer_size: 1024,    // Common power-of-two buffer size
            time_constant: 0.8,   // Standard analyzer time constant
            max_channel_count: 2, // Standard maximum channels
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityContext;
    
    fn create_test_audio_protection() -> AudioProtection {
        let security_context = SecurityContext::new(10);
        let manager = FingerprintManager::new(security_context);
        AudioProtection::new(manager)
    }
    
    #[test]
    fn test_audio_buffer_protection() {
        let protection = create_test_audio_protection();
        
        // Create a test audio buffer
        let mut buffer = [0.0, 0.5, -0.5, 0.0, 0.25, -0.25];
        let original = buffer;
        
        // Apply protection
        protection.protect_audio_buffer(&mut buffer, "example.com").unwrap();
        
        // Values should be slightly modified
        for i in 0..buffer.len() {
            assert_ne!(buffer[i], original[i]);
            
            // Changes should be subtle
            assert!((buffer[i] - original[i]).abs() < 0.001);
        }
    }
    
    #[test]
    fn test_frequency_data_protection() {
        let protection = create_test_audio_protection();

        // Test with multiple domains to ensure the protection is working
        let test_cases = vec![
            ("example1.com"),
            ("example2.com"),
            ("example3.com"),
            ("example4.com"),
        ];

        let mut found_change = false;

        for domain in test_cases {
            let mut data = [0, 64, 128, 192, 255];
            let original = data;

            // Apply protection
            protection.protect_frequency_data(&mut data, domain).unwrap();

            // Check if this particular domain resulted in a change
            if data.iter().zip(original.iter()).any(|(a, b)| a != b) {
                found_change = true;

                // But changes should be subtle
                for i in 0..data.len() {
                    assert!((data[i] as i32 - original[i] as i32).abs() < 3);
                }
            }

            // Should be deterministic - same domain should give same result
            let mut data2 = [0, 64, 128, 192, 255];
            protection.protect_frequency_data(&mut data2, domain).unwrap();
            assert_eq!(data, data2);
        }

        // At least one domain should have caused changes
        assert!(found_change, "Expected at least one domain to modify frequency data");
    }
    
    #[test]
    fn test_audio_param_normalization() {
        let protection = create_test_audio_protection();
        
        // Get normalized parameters
        let params = protection.normalize_audio_params("example.com");
        
        // Check that values are standardized
        assert_eq!(params.sample_rate, 44100.0);
        assert_eq!(params.channel_count, 2);
        assert_eq!(params.buffer_size, 1024);
    }
    
    #[test]
    fn test_known_fingerprinting_domains() {
        let protection = create_test_audio_protection();
        
        // Known fingerprinting domains should be mocked
        assert!(protection.should_mock_audio_api("fingerprint.com"));
        assert!(protection.should_mock_audio_api("analytics.example.com"));
        assert!(protection.should_mock_audio_api("amplitude.tracking.com"));
        
        // Regular domains should not be mocked
        assert!(!protection.should_mock_audio_api("example.com"));
        assert!(!protection.should_mock_audio_api("trusted-site.org"));
    }
} 
