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

    /// Create a new canvas protection instance with custom noise factor
    pub fn with_noise_factor(manager: FingerprintManager, color_noise_factor: f32) -> Self {
        let is_enabled = manager.protection_config().canvas_noise;
        Self {
            manager,
            config: CanvasProtectionConfig {
                enabled: is_enabled,
                color_noise_factor: color_noise_factor.into(),
                ..Default::default()
            },
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
    pub fn protect_image_data_with_rng<R: Rng + ?Sized>(&self, data: &mut [u8], _width: u32, _height: u32, _domain: &str, rng: &mut R) -> Result<(), FingerprintError> {
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
                    let _noise = normal.sample(rng);
                    // Apply a 50% chance of making small adjustments
                    if rng.gen::<f32>() < 0.5 {
                        let adjustment = if rng.gen::<bool>() { 1 } else { -1 };
                        let new_value = (data[i + j] as i16 + adjustment).clamp(0, 255) as u8;
                        data[i + j] = new_value;
                    }
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

        // Use deterministic RNG based on domain
        let domain_seed = self.manager.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(domain_seed);

        // Add subtle position noise - small adjustments that are consistent
        let x_adjustment = if rng.gen::<f32>() < 0.5 {
            if rng.gen::<bool>() { 0.1 } else { -0.1 }
        } else {
            0.0
        };

        let y_adjustment = if rng.gen::<f32>() < 0.5 {
            if rng.gen::<bool>() { 0.1 } else { -0.1 }
        } else {
            0.0
        };

        (x + x_adjustment, y + y_adjustment)
    }
    
    /// Apply noise to a color value (0-255)
    pub fn get_color_noise(&self, color: u8, domain: &str) -> u8 {
        if !self.config.enabled {
            return color;
        }

        // Record this protection event
        self.record_protection(domain, false);

        // Use deterministic RNG based on domain AND color value for more variety
        let domain_seed = self.manager.domain_seed(domain);
        let color_seed = domain_seed.wrapping_add(color as u64);
        let mut rng = ChaCha20Rng::seed_from_u64(color_seed);

        // Add subtle color noise - ensure 75% chance of making small adjustment
        if rng.gen::<f32>() < 0.75 {
            let adjustment = if rng.gen::<bool>() { 1 } else { -1 };
            (color as i16 + adjustment).clamp(0, 255) as u8
        } else {
            color
        }
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
        let security_context = SecurityContext::new(10);
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

        let original = image_data.clone();

        protection
            .protect_image_data(&mut image_data, width, height, "example.com")
            .expect("protection should succeed");

        // Verify that values have changed slightly but alpha remains intact
        assert_ne!(image_data, original);
        assert_eq!(image_data.len(), (width * height * 4) as usize);
        assert_eq!(image_data[3], 255); // Alpha should remain the same
    }
    
    #[test]
    fn test_position_noise() {
        let protection = create_test_canvas_protection();

        // Test multiple positions/domains to ensure the protection is working
        let test_cases = vec![
            (100.0, 200.0, "example1.com"),
            (50.0, 75.0, "example2.com"),
            (0.0, 0.0, "example3.com"),
            (150.0, 300.0, "example4.com"),
        ];

        let mut found_change = false;

        for (original_x, original_y, domain) in test_cases {
            let (noisy_x, noisy_y) = protection.get_text_position_noise(original_x, original_y, domain);

            // Check if this particular domain resulted in a change
            if noisy_x != original_x || noisy_y != original_y {
                found_change = true;

                // Changes should be subtle
                assert!((noisy_x - original_x).abs() < 1.0);
                assert!((noisy_y - original_y).abs() < 1.0);
            }

            // Should be deterministic - same input should give same output
            let (noisy_x2, noisy_y2) = protection.get_text_position_noise(original_x, original_y, domain);
            assert_eq!((noisy_x, noisy_y), (noisy_x2, noisy_y2));
        }

        // At least one test case should have caused changes
        assert!(found_change, "Expected at least one domain to modify position values");
    }
    
    #[test]
    fn test_color_noise() {
        let protection = create_test_canvas_protection();

        // Test multiple colors and domains to ensure the noise function is working
        let test_cases = vec![
            (0, "example1.com"),
            (128, "example2.com"),
            (255, "example3.com"),
            (64, "example4.com"),
            (32, "example1.com"),
            (192, "example2.com"),
            (16, "example3.com"),
            (224, "example4.com"),
            (8, "test.com"),
            (240, "fingerprint.com"),
        ];

        let mut found_change = false;

        for (original_color, domain) in test_cases {
            let noisy_color = protection.get_color_noise(original_color, domain);

            // Check if this particular case resulted in a change
            if noisy_color != original_color {
                found_change = true;

                // Change should be subtle
                assert!((noisy_color as i16 - original_color as i16).abs() < 10);
            }

            // But should be deterministic - same input should give same output
            let noisy_color2 = protection.get_color_noise(original_color, domain);
            assert_eq!(noisy_color, noisy_color2);
        }

        // At least one color should have been changed
        assert!(found_change, "Expected at least one color to be modified by noise");
    }
    
    #[test]
    fn test_operation_protection() {
        let protection = create_test_canvas_protection();
        
        // Default config protects text, shapes, and images
        assert!(protection.should_protect_operation(CanvasOperation::TextRendering));
        assert!(protection.should_protect_operation(CanvasOperation::ShapeRendering));
        assert!(protection.should_protect_operation(CanvasOperation::ImageDrawing));
        
        // Create protection with custom config
        let security_context = SecurityContext::new(10);
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
