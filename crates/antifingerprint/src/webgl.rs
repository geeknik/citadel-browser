//! WebGL fingerprinting protection
//!
//! WebGL can be used for highly accurate fingerprinting through renderer information,
//! parameters, extensions, and rendering behavior. This module provides protections
//! against these fingerprinting techniques.

use crate::{FingerprintManager, FingerprintError, metrics::ProtectionType};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// WebGL parameter types that can be protected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebGLParameter {
    /// Renderer string (UNMASKED_RENDERER_WEBGL)
    Renderer,
    /// Vendor string (UNMASKED_VENDOR_WEBGL)
    Vendor,
    /// Version string (VERSION or SHADING_LANGUAGE_VERSION)
    Version,
    /// Extensions list
    Extensions,
    /// Maximum render buffer size
    MaxRenderBufferSize,
    /// Maximum texture size
    MaxTextureSize,
    /// Maximum viewport dimensions
    MaxViewportDims,
    /// Other numeric parameters
    NumericParameter,
}

/// Normalized WebGL renderer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebGLInfo {
    /// WebGL vendor string
    pub vendor: String,
    /// WebGL renderer string
    pub renderer: String,
    /// WebGL version
    pub version: String,
    /// Shading language version
    pub shading_language_version: String,
    /// Available extensions (normalized)
    pub extensions: Vec<String>,
    /// Maximum texture size
    pub max_texture_size: u32,
    /// Maximum render buffer size
    pub max_render_buffer_size: u32,
    /// Maximum viewport width
    pub max_viewport_width: u32,
    /// Maximum viewport height 
    pub max_viewport_height: u32,
}

/// Standard WebGL configurations for normalized fingerprints
#[derive(Debug, Clone, Copy)]
pub enum WebGLStandardConfig {
    /// Intel integrated graphics
    IntelHD,
    /// NVIDIA GeForce
    NvidiaGeForce,
    /// AMD Radeon
    AMDRadeon,
    /// Apple Metal
    AppleMetal,
}

impl WebGLStandardConfig {
    /// Get a standard configuration for WebGL
    pub fn get_config(&self) -> WebGLInfo {
        match self {
            WebGLStandardConfig::IntelHD => WebGLInfo {
                vendor: "Intel Inc.".to_string(),
                renderer: "Intel(R) HD Graphics 630".to_string(),
                version: "WebGL 2.0 (OpenGL ES 3.0)".to_string(),
                shading_language_version: "WebGL GLSL ES 3.00".to_string(),
                extensions: vec![
                    "ANGLE_instanced_arrays".to_string(),
                    "EXT_blend_minmax".to_string(),
                    "EXT_color_buffer_half_float".to_string(),
                    "EXT_texture_filter_anisotropic".to_string(),
                    "OES_element_index_uint".to_string(),
                    "OES_standard_derivatives".to_string(),
                    "OES_texture_float".to_string(),
                    "OES_texture_half_float".to_string(),
                    "OES_vertex_array_object".to_string(),
                    "WEBGL_debug_renderer_info".to_string(),
                ],
                max_texture_size: 16384,
                max_render_buffer_size: 16384,
                max_viewport_width: 16384,
                max_viewport_height: 16384,
            },
            WebGLStandardConfig::NvidiaGeForce => WebGLInfo {
                vendor: "NVIDIA Corporation".to_string(),
                renderer: "NVIDIA GeForce RTX 3070".to_string(),
                version: "WebGL 2.0 (OpenGL ES 3.0)".to_string(),
                shading_language_version: "WebGL GLSL ES 3.00".to_string(),
                extensions: vec![
                    "ANGLE_instanced_arrays".to_string(),
                    "EXT_blend_minmax".to_string(),
                    "EXT_color_buffer_half_float".to_string(),
                    "EXT_texture_filter_anisotropic".to_string(),
                    "OES_element_index_uint".to_string(),
                    "OES_standard_derivatives".to_string(),
                    "OES_texture_float".to_string(),
                    "OES_texture_half_float".to_string(),
                    "OES_vertex_array_object".to_string(),
                    "WEBGL_debug_renderer_info".to_string(),
                ],
                max_texture_size: 32768,
                max_render_buffer_size: 32768,
                max_viewport_width: 32768,
                max_viewport_height: 32768,
            },
            WebGLStandardConfig::AMDRadeon => WebGLInfo {
                vendor: "AMD".to_string(),
                renderer: "AMD Radeon RX 6800 XT".to_string(),
                version: "WebGL 2.0 (OpenGL ES 3.0)".to_string(),
                shading_language_version: "WebGL GLSL ES 3.00".to_string(),
                extensions: vec![
                    "ANGLE_instanced_arrays".to_string(),
                    "EXT_blend_minmax".to_string(),
                    "EXT_color_buffer_half_float".to_string(),
                    "EXT_texture_filter_anisotropic".to_string(),
                    "OES_element_index_uint".to_string(),
                    "OES_standard_derivatives".to_string(),
                    "OES_texture_float".to_string(),
                    "OES_texture_half_float".to_string(),
                    "OES_vertex_array_object".to_string(),
                    "WEBGL_debug_renderer_info".to_string(),
                ],
                max_texture_size: 32768,
                max_render_buffer_size: 32768,
                max_viewport_width: 32768,
                max_viewport_height: 32768,
            },
            WebGLStandardConfig::AppleMetal => WebGLInfo {
                vendor: "Apple Inc.".to_string(),
                renderer: "Apple M1 Pro".to_string(),
                version: "WebGL 2.0 (OpenGL ES 3.0 Metal - 76.3)".to_string(),
                shading_language_version: "WebGL GLSL ES 3.00".to_string(),
                extensions: vec![
                    "ANGLE_instanced_arrays".to_string(),
                    "EXT_blend_minmax".to_string(),
                    "EXT_color_buffer_half_float".to_string(),
                    "EXT_texture_filter_anisotropic".to_string(),
                    "OES_element_index_uint".to_string(),
                    "OES_standard_derivatives".to_string(),
                    "OES_texture_float".to_string(),
                    "OES_texture_half_float".to_string(),
                    "OES_vertex_array_object".to_string(),
                    "WEBGL_debug_renderer_info".to_string(),
                ],
                max_texture_size: 16384,
                max_render_buffer_size: 16384,
                max_viewport_width: 16384,
                max_viewport_height: 16384,
            },
        }
    }
}

/// WebGL fingerprinting protection
#[derive(Debug)]
pub struct WebGLProtection {
    /// Reference to the fingerprint manager
    manager: FingerprintManager,
    /// Whether WebGL protection is enabled
    enabled: bool,
    /// Normalized WebGL info
    normalized_info: Option<WebGLInfo>,
    /// Optional metrics tracker
    metrics: Option<Arc<crate::metrics::FingerprintMetrics>>,
}

impl WebGLProtection {
    /// Create a new WebGL protection instance
    pub fn new(manager: FingerprintManager) -> Self {
        let enabled = manager.protection_config().spoof_webgl;
        
        Self {
            manager,
            enabled,
            normalized_info: None,
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
                metrics.record_blocked(ProtectionType::WebGL, domain);
            } else {
                metrics.record_normalized(ProtectionType::WebGL, domain);
            }
        }
    }
    
    /// Initialize with the real WebGL info from the browser
    pub fn with_real_webgl(&mut self, real_info: WebGLInfo) -> Result<(), FingerprintError> {
        if !self.enabled {
            // If protection is disabled, store the real info
            self.normalized_info = Some(real_info);
            return Ok(());
        }
        
        // Determine which standard profile to use based on the real info
        let config = self.select_standard_config(&real_info);
        self.normalized_info = Some(config.get_config());
        
        // Record this protection event with a placeholder domain
        self.record_protection("initialization", false);
        
        Ok(())
    }
    
    /// Select a standard WebGL configuration based on the real hardware
    fn select_standard_config(&self, real_info: &WebGLInfo) -> WebGLStandardConfig {
        let renderer_lower = real_info.renderer.to_lowercase();
        let vendor_lower = real_info.vendor.to_lowercase();
        
        if vendor_lower.contains("nvidia") {
            WebGLStandardConfig::NvidiaGeForce
        } else if vendor_lower.contains("amd") || vendor_lower.contains("radeon") || renderer_lower.contains("radeon") {
            WebGLStandardConfig::AMDRadeon
        } else if vendor_lower.contains("apple") || renderer_lower.contains("apple") {
            WebGLStandardConfig::AppleMetal
        } else {
            // Default to Intel HD for generic or unknown hardware
            WebGLStandardConfig::IntelHD
        }
    }
    
    /// Get the normalized WebGL information
    pub fn get_webgl_info(&self) -> Option<&WebGLInfo> {
        self.normalized_info.as_ref()
    }
    
    /// Get a normalized value for a WebGL parameter
    pub fn get_parameter_value(&self, param: WebGLParameter, domain: &str) -> Option<String> {
        if !self.enabled || self.normalized_info.is_none() {
            return None;
        }
        
        // Record this protection event
        self.record_protection(domain, false);
        
        let info = self.normalized_info.as_ref().unwrap();
        
        match param {
            WebGLParameter::Renderer => Some(info.renderer.clone()),
            WebGLParameter::Vendor => Some(info.vendor.clone()),
            WebGLParameter::Version => Some(info.version.clone()),
            _ => None,
        }
    }
    
    /// Modify a shader to prevent precision-based fingerprinting
    pub fn normalize_shader(&self, shader_source: &str, domain: &str) -> String {
        if !self.enabled {
            return shader_source.to_string();
        }
        
        // Record this protection event
        self.record_protection(domain, false);
        
        // This is a simplified implementation - a real one would parse and
        // transform the shader code to standardize precision
        let mut result = shader_source.to_string();
        
        // Replace any "highp" precision with "mediump" to reduce uniqueness
        result = result.replace("highp", "mediump");
        
        result
    }
    
    /// Normalize vertices to protect against drawing-based fingerprinting
    pub fn normalize_vertices(&self, vertices: &mut [f32], domain: &str) -> Result<(), FingerprintError> {
        if !self.enabled {
            return Ok(());
        }
        
        // Record this protection event
        self.record_protection(domain, false);
        
        // Add subtle noise to vertex positions to prevent drawing-based fingerprinting
        for vertex in vertices.iter_mut() {
            *vertex = self.manager.apply_noise_f32(*vertex, 0.0001, domain);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityContext;
    
    fn create_test_webgl_protection() -> WebGLProtection {
        let security_context = SecurityContext::new(10);
        let manager = FingerprintManager::new(security_context);
        WebGLProtection::new(manager)
    }
    
    fn create_test_webgl_info() -> WebGLInfo {
        WebGLInfo {
            vendor: "NVIDIA Corporation".to_string(),
            renderer: "NVIDIA GeForce RTX 2080".to_string(),
            version: "WebGL 2.0".to_string(),
            shading_language_version: "WebGL GLSL ES 3.00".to_string(),
            extensions: vec![
                "EXT_texture_filter_anisotropic".to_string(),
                "OES_texture_float".to_string(),
                "WEBGL_debug_renderer_info".to_string(),
            ],
            max_texture_size: 16384,
            max_render_buffer_size: 16384,
            max_viewport_width: 16384,
            max_viewport_height: 16384,
        }
    }
    
    #[test]
    fn test_webgl_normalization() {
        let mut protection = create_test_webgl_protection();
        let real_info = create_test_webgl_info();
        
        // Initialize with real info
        protection.with_real_webgl(real_info.clone()).unwrap();
        
        // Get normalized info
        let normalized = protection.get_webgl_info().unwrap();
        
        // Should standardize to a known NVIDIA config
        assert_eq!(normalized.vendor, "NVIDIA Corporation");
        assert_eq!(normalized.renderer, "NVIDIA GeForce RTX 3070"); // Normalized to standard model
        
        // Should have standard parameters
        assert_eq!(normalized.max_texture_size, 32768);
        
        // Should have standard extensions
        assert!(normalized.extensions.contains(&"EXT_texture_filter_anisotropic".to_string()));
    }
    
    #[test]
    fn test_parameter_normalization() {
        let mut protection = create_test_webgl_protection();
        let real_info = create_test_webgl_info();
        
        protection.with_real_webgl(real_info).unwrap();
        
        // Test renderer normalization
        let renderer = protection.get_parameter_value(WebGLParameter::Renderer, "example.com").unwrap();
        assert_eq!(renderer, "NVIDIA GeForce RTX 3070");
        
        // Test vendor normalization
        let vendor = protection.get_parameter_value(WebGLParameter::Vendor, "example.com").unwrap();
        assert_eq!(vendor, "NVIDIA Corporation");
    }
    
    #[test]
    fn test_shader_normalization() {
        let protection = create_test_webgl_protection();
        
        let shader = "precision highp float; uniform highp vec2 resolution;";
        let normalized = protection.normalize_shader(shader, "example.com");
        
        // Should replace highp with mediump
        assert_eq!(normalized, "precision mediump float; uniform mediump vec2 resolution;");
    }
    
    #[test]
    fn test_vertex_normalization() {
        let protection = create_test_webgl_protection();
        
        let mut vertices = [0.0, 1.0, 0.5, -1.0];
        let original = vertices.clone();
        
        protection.normalize_vertices(&mut vertices, "example.com").unwrap();
        
        // Values should be slightly modified
        for i in 0..vertices.len() {
            assert_ne!(vertices[i], original[i]);
            
            // But changes should be subtle
            assert!((vertices[i] - original[i]).abs() < 0.001);
        }
    }
    
    #[test]
    fn test_standard_config_selection() {
        let protection = create_test_webgl_protection();
        
        // Test NVIDIA detection
        let mut info = create_test_webgl_info();
        info.vendor = "NVIDIA Corporation".to_string();
        let config = protection.select_standard_config(&info);
        assert!(matches!(config, WebGLStandardConfig::NvidiaGeForce));
        
        // Test AMD detection
        info.vendor = "AMD".to_string();
        let config = protection.select_standard_config(&info);
        assert!(matches!(config, WebGLStandardConfig::AMDRadeon));
        
        // Test Apple detection
        info.vendor = "Apple Inc.".to_string();
        let config = protection.select_standard_config(&info);
        assert!(matches!(config, WebGLStandardConfig::AppleMetal));
        
        // Test default (Intel)
        info.vendor = "Unknown Vendor".to_string();
        let config = protection.select_standard_config(&info);
        assert!(matches!(config, WebGLStandardConfig::IntelHD));
    }
} 