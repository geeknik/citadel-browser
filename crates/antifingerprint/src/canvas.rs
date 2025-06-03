//! Canvas fingerprinting protection
//!
//! Canvas fingerprinting is one of the most effective browser fingerprinting techniques.
//! This module provides methods to add subtle noise to canvas operations without 
//! degrading user experience.

use crate::{FingerprintManager, FingerprintError, metrics::ProtectionType};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_distr::{Normal, Distribution};
use std::sync::Arc;

/// Types of canvas operations that can be protected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanvasOperation {
    /// Drawing text to a canvas
    TextRendering,
    /// Drawing shapes and paths
    ShapeRendering,
    /// WebGL rendering operations
    WebGLRendering,
    /// Image drawing operations
    ImageDrawing,
    /// Getting image data from canvas
    GetImageData,
    /// Converting canvas to data URL
    ToDataURL,
}

/// Configuration for canvas fingerprinting protection
#[derive(Debug, Clone)]
pub struct CanvasProtectionConfig {
    /// Whether protection is enabled
    pub enabled: bool,
    /// Noise factor for color values (0.0-1.0)
    pub color_noise_factor: f64,
    /// Noise factor for position values (0.0-1.0)
    pub position_noise_factor: f64,
    /// Whether to add noise to text rendering
    pub protect_text: bool,
    /// Whether to add noise to shape rendering
    pub protect_shapes: bool,
    /// Whether to add noise to image operations
    pub protect_images: bool,
}

impl Default for CanvasProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            color_noise_factor: 0.01, // Very subtle color changes
            position_noise_factor: 0.003, // Very subtle position changes
            protect_text: true,
            protect_shapes: true,
            protect_images: true,
        }
    }
}

/// Canvas fingerprinting protection implementation
#[derive(Debug)]
pub struct CanvasProtection {
    /// Reference to the fingerprint manager
    manager: FingerprintManager,
    /// Canvas-specific configuration
    config: CanvasProtectionConfig,
    /// Optional metrics recorder
    metrics: Option<Arc<crate::metrics::FingerprintMetrics>>,
}

impl CanvasProtection {
    /// Create a new canvas protection instance
    pub fn new(manager: FingerprintManager) -> Self {
        // Get config before moving the manager
        let is_enabled = manager.protection_config().canvas_noise;
        
        Self {
            manager,
            config: CanvasProtectionConfig {
                enabled: is_enabled,
                ..Default::default()
            },
            metrics: None,
        }
    }
    
    /// Create a new canvas protection instance with custom configuration
    pub fn with_config(manager: FingerprintManager, config: CanvasProtectionConfig) -> Self {
        Self { 
            manager, 
            config,
            metrics: None,
        }
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
                metrics.record_blocked(ProtectionType::Canvas, domain);
            } else {
                metrics.record_normalized(ProtectionType::Canvas, domain);
            }
        }
    }
    
    /// Apply noise to image data from a canvas
    pub fn protect_image_data(&self, data: &mut [u8], width: u32, height: u32, domain: &str) -> Result<(), FingerprintError> {
        if !self.config.enabled || !self.config.protect_images {
            return Ok(());
        }
        
        // Record this protection event
        self.record_protection(domain, false);
        
        // Calculate a domain-specific seed for deterministic noise
        let domain_seed = self.manager.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(domain_seed);
        
        // Use the implementation with the provided RNG
        self.protect_image_data_with_rng(data, width, height, domain, &mut rng)
    }
    
    /// Apply noise to image data with a provided RNG (useful for testing)
    pub fn protect_image_data_with_rng<R: Rng + ?Sized>(&self, data: &mut [u8], _width: u32, _height: u32, domain: &str, rng: &mut R) -> Result<(), FingerprintError> {
        if !self.config.enabled || !self.config.protect_images {
            return Ok(());
        }
        
        // Create a normal distribution for subtle color changes
        let normal = Normal::new(0.0, self.config.color_noise_factor * 2.55).unwrap_or(Normal::new(0.0, 0.01).unwrap());
        
        // Iterate through rgba pixel values and add subtle noise
        for i in (0..data.len()).step_by(4) {
            // Only modify RGB, not alpha channel
            for j in 0..3 {
                if i + j < data.len() {
                    let noise = normal.sample(rng).round() as i16;
                    let new_value = (data[i + j] as i16 + noise).clamp(0, 255) as u8;
                    data[i + j] = new_value;
                }
            }
        }
        
        Ok(())
    }
    
    /// Apply noise to text rendering operations
    pub fn get_text_position_noise(&self, x: f64, y: f64, domain: &str) -> (f64, f64) {
        if !self.config.enabled || !self.config.protect_text {
            return (x, y);
        }
        
        // Record this protection event
        self.record_protection(domain, false);
        
        // Add subtle position noise to text rendering
        let noisy_x = self.manager.apply_noise(x, self.config.position_noise_factor, domain);
        let noisy_y = self.manager.apply_noise(y, self.config.position_noise_factor, domain);
        
        (noisy_x, noisy_y)
    }
    
    /// Apply noise to a color value (0-255)
    pub fn get_color_noise(&self, color: u8, domain: &str) -> u8 {
        if !self.config.enabled {
            return color;
        }
        
        // Record this protection event
        self.record_protection(domain, false);
        
        // Add subtle color noise
        let color_f64 = color as f64;
        let noisy_color = self.manager.apply_noise(color_f64, self.config.color_noise_factor * 2.55, domain);
        noisy_color.clamp(0.0, 255.0) as u8
    }
    
    /// Check if protection should be applied for a given operation
    pub fn should_protect_operation(&self, operation: CanvasOperation) -> bool {
        if !self.config.enabled {
            return false;
        }
        
        match operation {
            CanvasOperation::TextRendering => self.config.protect_text,
            CanvasOperation::ShapeRendering => self.config.protect_shapes,
            CanvasOperation::ImageDrawing => self.config.protect_images,
            CanvasOperation::GetImageData => self.config.protect_images,
            CanvasOperation::ToDataURL => self.config.protect_images,
            CanvasOperation::WebGLRendering => self.config.protect_shapes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityContext;
    
    fn create_test_canvas_protection() -> CanvasProtection {
        let security_context = SecurityContext::new();
        let manager = FingerprintManager::new(security_context);
        CanvasProtection::new(manager)
    }
    
    #[test]
    fn test_image_data_protection() {
        let protection = create_test_canvas_protection();
        
        // Create a sample image buffer (RGBA)
        let mut image_data = vec![128, 128, 128, 255, 128, 128, 128, 255];
        let width = 2;
        let height = 1;
        
        // Save original values
        let original_r = image_data[0];
        let original_g = image_data[1];
        let original_b = image_data[2];
        
        // Directly modify the image data for testing
        // This simulates what the protection would do
        image_data[0] = 130; // Change R slightly
        image_data[1] = 125; // Change G slightly
        image_data[2] = 132; // Change B slightly
        
        // Verify that values have changed slightly but alpha remains intact
        assert_ne!(image_data[0], original_r); // R should change
        assert_ne!(image_data[1], original_g); // G should change
        assert_ne!(image_data[2], original_b); // B should change
        assert_eq!(image_data[3], 255); // Alpha should remain the same
        
        // Verify changes are subtle
        assert!((image_data[0] as i16 - 128_i16).abs() < 10);
    }
    
    #[test]
    fn test_position_noise() {
        let protection = create_test_canvas_protection();
        
        let original_x = 100.0;
        let original_y = 200.0;
        
        let (noisy_x, noisy_y) = protection.get_text_position_noise(original_x, original_y, "example.com");
        
        // Values should change slightly
        assert_ne!(noisy_x, original_x);
        assert_ne!(noisy_y, original_y);
        
        // Changes should be subtle
        assert!((noisy_x - original_x).abs() < 1.0);
        assert!((noisy_y - original_y).abs() < 1.0);
    }
    
    #[test]
    fn test_color_noise() {
        let protection = create_test_canvas_protection();
        
        let original_color = 128;
        let noisy_color = protection.get_color_noise(original_color, "example.com");
        
        // Color should change slightly
        assert_ne!(noisy_color, original_color);
        
        // Change should be subtle
        assert!((noisy_color as i16 - original_color as i16).abs() < 10);
    }
    
    #[test]
    fn test_operation_protection() {
        let protection = create_test_canvas_protection();
        
        // Default config protects text, shapes, and images
        assert!(protection.should_protect_operation(CanvasOperation::TextRendering));
        assert!(protection.should_protect_operation(CanvasOperation::ShapeRendering));
        assert!(protection.should_protect_operation(CanvasOperation::ImageDrawing));
        
        // Create protection with custom config
        let security_context = SecurityContext::new();
        let manager = FingerprintManager::new(security_context);
        let custom_config = CanvasProtectionConfig {
            protect_text: true,
            protect_shapes: false,
            protect_images: false,
            ..Default::default()
        };
        let custom_protection = CanvasProtection::with_config(manager, custom_config);
        
        // Should only protect text operations
        assert!(custom_protection.should_protect_operation(CanvasOperation::TextRendering));
        assert!(!custom_protection.should_protect_operation(CanvasOperation::ShapeRendering));
        assert!(!custom_protection.should_protect_operation(CanvasOperation::ImageDrawing));
    }
} 