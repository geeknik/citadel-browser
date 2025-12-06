//! Navigator fingerprinting protection
//!
//! This module implements protections against fingerprinting via the Navigator API,
//! which includes user agent, platform information, plugins, and other characteristics
//! that can be used to identify browsers.

use crate::FingerprintManager;
use serde::{Deserialize, Serialize};

/// Normalized browser categories for platform consistency
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserCategory {
    /// Chrome and Chromium-based browsers
    Chrome,
    /// Firefox and related browsers
    Firefox,
    /// Safari and WebKit-based browsers
    Safari,
    /// Edge (modern/Chromium-based)
    Edge,
    /// Opera
    Opera,
    /// Other browser types
    Other,
}

impl BrowserCategory {
    /// Get the browser category from a user agent string
    pub fn from_user_agent(user_agent: &str) -> Self {
        let ua_lower = user_agent.to_lowercase();
        
        if ua_lower.contains("firefox") {
            BrowserCategory::Firefox
        } else if ua_lower.contains("edg") || ua_lower.contains("edge") {
            BrowserCategory::Edge
        } else if ua_lower.contains("safari") && !ua_lower.contains("chrome") && !ua_lower.contains("android") {
            BrowserCategory::Safari
        } else if ua_lower.contains("opr") || ua_lower.contains("opera") {
            BrowserCategory::Opera
        } else if ua_lower.contains("chrome") {
            BrowserCategory::Chrome
        } else {
            BrowserCategory::Other
        }
    }
    
    /// Get a string representation for this browser category
    pub fn as_str(&self) -> &'static str {
        match self {
            BrowserCategory::Chrome => "chrome",
            BrowserCategory::Firefox => "firefox",
            BrowserCategory::Safari => "safari",
            BrowserCategory::Edge => "edge",
            BrowserCategory::Opera => "opera",
            BrowserCategory::Other => "other",
        }
    }
    
    /// Get a display name for this browser category
    pub fn display_name(&self) -> &'static str {
        match self {
            BrowserCategory::Chrome => "Google Chrome",
            BrowserCategory::Firefox => "Mozilla Firefox", 
            BrowserCategory::Safari => "Apple Safari",
            BrowserCategory::Edge => "Microsoft Edge",
            BrowserCategory::Opera => "Opera",
            BrowserCategory::Other => "Unknown Browser",
        }
    }
    
    /// Check if this browser category matches a string identifier
    pub fn matches_str(&self, identifier: &str) -> bool {
        self.as_str() == identifier.to_lowercase()
    }
}

/// Normalized navigator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigatorInfo {
    /// User Agent
    pub user_agent: String,
    /// Platform (e.g., "Win32", "MacIntel", "Linux x86_64")
    pub platform: String,
    /// Vendor (e.g., "Google Inc.", "Apple Computer, Inc.")
    pub vendor: String,
    /// Languages array (e.g., ["en-US", "en"])
    pub languages: Vec<String>,
    /// Hardware concurrency (CPU cores reported)
    pub hardware_concurrency: u32,
    /// Device memory in GB
    pub device_memory: Option<f64>,
    /// Maximum touch points
    pub max_touch_points: u32,
    /// Whether plugins are enabled
    pub plugins_enabled: bool,
    /// Whether do-not-track is enabled
    pub do_not_track: bool,
}

/// Navigator fingerprinting protection implementation
#[derive(Debug)]
pub struct NavigatorProtection {
    /// Reference to the fingerprint manager
    manager: FingerprintManager,
    /// Whether to normalize navigator properties
    enabled: bool,
    /// The standardized navigator info to use
    normalized_info: Option<NavigatorInfo>,
}

impl NavigatorProtection {
    /// Create a new navigator protection instance
    pub fn new(manager: FingerprintManager) -> Self {
        let enabled = manager.protection_config().normalize_navigator;
        
        Self {
            manager,
            enabled,
            normalized_info: None,
        }
    }
    
    /// Initialize with normalized navigator info
    pub fn with_real_navigator(&mut self, real_navigator: NavigatorInfo) {
        if !self.enabled {
            return;
        }
        
        let browser_category = BrowserCategory::from_user_agent(&real_navigator.user_agent);
        self.normalized_info = Some(self.normalize_navigator(real_navigator, browser_category));
    }
    
    /// Get the normalized navigator information
    pub fn get_navigator_info(&self) -> Option<&NavigatorInfo> {
        self.normalized_info.as_ref()
    }
    
    /// Log a navigator access attempt
    pub fn log_access_attempt(&self, property: &str) {
        if self.enabled {
            self.manager.log_attempt("navigator", property);
        }
    }
    
    /// Normalize navigator information based on browser category
    fn normalize_navigator(&self, real: NavigatorInfo, category: BrowserCategory) -> NavigatorInfo {
        if !self.enabled {
            return real;
        }
        
        // Keep the real browser category but normalize fingerprinting factors
        match category {
            BrowserCategory::Chrome => NavigatorInfo {
                // Keep real UA but standardize platform and hardware metrics
                user_agent: real.user_agent,
                platform: self.normalize_platform(&real.platform),
                vendor: "Google Inc.".to_string(),
                languages: real.languages,
                hardware_concurrency: self.normalize_hardware_concurrency(real.hardware_concurrency),
                device_memory: Some(8.0), // Standardize to 8GB
                max_touch_points: if real.max_touch_points > 0 { 5 } else { 0 },
                plugins_enabled: false, // Disable plugins for privacy
                do_not_track: real.do_not_track,
            },
            BrowserCategory::Firefox => NavigatorInfo {
                user_agent: real.user_agent,
                platform: self.normalize_platform(&real.platform),
                vendor: "".to_string(), // Firefox typically has empty vendor
                languages: real.languages,
                hardware_concurrency: self.normalize_hardware_concurrency(real.hardware_concurrency),
                device_memory: None, // Firefox doesn't support device_memory
                max_touch_points: if real.max_touch_points > 0 { 5 } else { 0 },
                plugins_enabled: false,
                do_not_track: real.do_not_track,
            },
            BrowserCategory::Safari => NavigatorInfo {
                user_agent: real.user_agent,
                platform: self.normalize_platform(&real.platform),
                vendor: "Apple Computer, Inc.".to_string(),
                languages: real.languages,
                hardware_concurrency: self.normalize_hardware_concurrency(real.hardware_concurrency),
                device_memory: None, // Safari doesn't support device_memory
                max_touch_points: if real.max_touch_points > 0 { 5 } else { 0 },
                plugins_enabled: false,
                do_not_track: real.do_not_track,
            },
            _ => {
                // For other browsers, apply general normalization
                NavigatorInfo {
                    user_agent: real.user_agent,
                    platform: self.normalize_platform(&real.platform),
                    vendor: real.vendor,
                    languages: real.languages,
                    hardware_concurrency: self.normalize_hardware_concurrency(real.hardware_concurrency),
                    device_memory: Some(8.0),
                    max_touch_points: if real.max_touch_points > 0 { 5 } else { 0 },
                    plugins_enabled: false,
                    do_not_track: real.do_not_track,
                }
            }
        }
    }
    
    /// Normalize platform string to reduce entropy
    fn normalize_platform(&self, platform: &str) -> String {
        let platform_lower = platform.to_lowercase();
        
        if platform_lower.contains("win") {
            "Win32".to_string()
        } else if platform_lower.contains("mac") || platform_lower.contains("iphone") || platform_lower.contains("ipad") {
            "MacIntel".to_string()
        } else if platform_lower.contains("linux") || platform_lower.contains("android") {
            "Linux x86_64".to_string()
        } else {
            platform.to_string()
        }
    }
    
    /// Normalize hardware concurrency to standard values
    fn normalize_hardware_concurrency(&self, real_cores: u32) -> u32 {
        // Round to common values to reduce uniqueness
        if real_cores <= 2 {
            2
        } else if real_cores <= 4 {
            4
        } else if real_cores <= 8 {
            8
        } else {
            16
        }
    }
    
    /// Get a normalized user agent string
    pub fn get_normalized_user_agent(&self, real_ua: &str) -> String {
        if !self.enabled {
            return real_ua.to_string();
        }
        
        if let Some(info) = &self.normalized_info {
            return info.user_agent.clone();
        }
        
        // If we haven't initialized with a real navigator yet,
        // do basic normalization on the provided UA
        let category = BrowserCategory::from_user_agent(real_ua);
        
        match category {
            BrowserCategory::Chrome => {
                // Keep major version but standardize the rest
                if let Some(idx) = real_ua.find("Chrome/") {
                    let version_start = idx + "Chrome/".len();
                    if let Some(end_idx) = real_ua[version_start..].find(' ') {
                        let version = &real_ua[version_start..version_start + end_idx];
                        if let Some(dot_idx) = version.find('.') {
                            let major = &version[..dot_idx];
                            // Construct a standardized Chrome UA with the same major version
                            return format!(
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
                                major
                            );
                        }
                    }
                }
            }
            BrowserCategory::Firefox => {
                if let Some(idx) = real_ua.find("Firefox/") {
                    let version_start = idx + "Firefox/".len();
                    if let Some(end_idx) = real_ua[version_start..].find(' ') {
                        let version_end = if end_idx > 0 { version_start + end_idx } else { real_ua.len() };
                        let version = &real_ua[version_start..version_end];
                        if let Some(dot_idx) = version.find('.') {
                            let major = &version[..dot_idx];
                            return format!(
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{}.0) Gecko/20100101 Firefox/{}.0",
                                major, major
                            );
                        }
                    }
                }
            }
            _ => {
                // For other browsers, return as-is for now
                return real_ua.to_string();
            }
        }
        
        real_ua.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityContext;
    
    fn create_test_navigator_protection() -> NavigatorProtection {
        let security_context = SecurityContext::new(10);
        let manager = FingerprintManager::new(security_context);
        NavigatorProtection::new(manager)
    }
    
    #[test]
    fn test_browser_category_detection() {
        // Chrome
        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
        assert_eq!(BrowserCategory::from_user_agent(chrome_ua), BrowserCategory::Chrome);
        
        // Firefox
        let firefox_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0";
        assert_eq!(BrowserCategory::from_user_agent(firefox_ua), BrowserCategory::Firefox);
        
        // Safari
        let safari_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15";
        assert_eq!(BrowserCategory::from_user_agent(safari_ua), BrowserCategory::Safari);
        
        // Edge
        let edge_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59";
        assert_eq!(BrowserCategory::from_user_agent(edge_ua), BrowserCategory::Edge);
    }
    
    #[test]
    fn test_browser_category_methods() {
        let chrome = BrowserCategory::Chrome;
        let firefox = BrowserCategory::Firefox;
        
        // Test as_str method
        assert_eq!(chrome.as_str(), "chrome");
        assert_eq!(firefox.as_str(), "firefox");
        
        // Test display_name method
        assert_eq!(chrome.display_name(), "Google Chrome");
        assert_eq!(firefox.display_name(), "Mozilla Firefox");
        
        // Test matches_str method
        assert!(chrome.matches_str("chrome"));
        assert!(chrome.matches_str("CHROME"));
        assert!(!chrome.matches_str("firefox"));
    }
    
    #[test]
    fn test_platform_normalization() {
        let protection = create_test_navigator_protection();
        
        assert_eq!(protection.normalize_platform("Windows"), "Win32");
        assert_eq!(protection.normalize_platform("Windows NT 10.0"), "Win32");
        assert_eq!(protection.normalize_platform("MacIntel"), "MacIntel");
        assert_eq!(protection.normalize_platform("iPhone"), "MacIntel");
        assert_eq!(protection.normalize_platform("Linux x86_64"), "Linux x86_64");
        assert_eq!(protection.normalize_platform("Linux aarch64"), "Linux x86_64");
        assert_eq!(protection.normalize_platform("Android"), "Linux x86_64");
    }
    
    #[test]
    fn test_hardware_concurrency_normalization() {
        let protection = create_test_navigator_protection();
        
        assert_eq!(protection.normalize_hardware_concurrency(1), 2);
        assert_eq!(protection.normalize_hardware_concurrency(2), 2);
        assert_eq!(protection.normalize_hardware_concurrency(3), 4);
        assert_eq!(protection.normalize_hardware_concurrency(4), 4);
        assert_eq!(protection.normalize_hardware_concurrency(6), 8);
        assert_eq!(protection.normalize_hardware_concurrency(8), 8);
        assert_eq!(protection.normalize_hardware_concurrency(12), 16);
        assert_eq!(protection.normalize_hardware_concurrency(16), 16);
        assert_eq!(protection.normalize_hardware_concurrency(24), 16);
    }
    
    #[test]
    fn test_user_agent_normalization() {
        let protection = create_test_navigator_protection();
        
        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
        let normalized_chrome = protection.get_normalized_user_agent(chrome_ua);
        
        assert!(normalized_chrome.contains("Chrome/91.0.0.0"));
        assert!(normalized_chrome.contains("Windows NT 10.0"));
        
        let firefox_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0";
        let normalized_firefox = protection.get_normalized_user_agent(firefox_ua);
        
        assert!(normalized_firefox.contains("Firefox/89.0"));
        assert!(normalized_firefox.contains("rv:89.0"));
    }
    
    #[test]
    fn test_navigator_info_normalization() {
        let mut protection = create_test_navigator_protection();
        
        let real_info = NavigatorInfo {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string(),
            platform: "Win32".to_string(),
            vendor: "Google Inc.".to_string(),
            languages: vec!["en-US".to_string(), "en".to_string()],
            hardware_concurrency: 6,
            device_memory: Some(4.0),
            max_touch_points: 0,
            plugins_enabled: true,
            do_not_track: false,
        };
        
        protection.with_real_navigator(real_info);
        
        let normalized = protection.get_navigator_info().unwrap();
        
        // Check normalization
        assert_eq!(normalized.hardware_concurrency, 8); // 6 rounded up to 8
        assert_eq!(normalized.device_memory, Some(8.0)); // Standardized to 8GB
        assert!(!normalized.plugins_enabled); // Disabled for privacy
    }
} 
