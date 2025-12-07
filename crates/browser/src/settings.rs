//! Settings and preferences management for Citadel Browser
//!
//! This module provides comprehensive configuration management with privacy
//! controls, security settings, and user preferences.

use std::collections::HashMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use citadel_networking::{PrivacyLevel, DnsMode};

/// Main settings structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserSettings {
    /// Privacy and security settings
    pub privacy: PrivacySettings,
    /// Network settings
    pub network: NetworkSettings,
    /// Content settings
    pub content: ContentSettings,
    /// User interface settings
    pub ui: UISettings,
    /// Performance settings
    pub performance: PerformanceSettings,
    /// Extension settings
    pub extensions: ExtensionSettings,
    /// Advanced settings
    pub advanced: AdvancedSettings,
}

impl Default for BrowserSettings {
    fn default() -> Self {
        Self {
            privacy: PrivacySettings::default(),
            network: NetworkSettings::default(),
            content: ContentSettings::default(),
            ui: UISettings::default(),
            performance: PerformanceSettings::default(),
            extensions: ExtensionSettings::default(),
            advanced: AdvancedSettings::default(),
        }
    }
}

/// Privacy and security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySettings {
    /// Global privacy level
    pub privacy_level: PrivacyLevel,
    /// Enable tracking protection
    pub tracking_protection: bool,
    /// Block third-party cookies
    pub block_third_party_cookies: bool,
    /// Clear browsing data on exit
    pub clear_data_on_exit: bool,
    /// Use private browsing mode by default
    pub private_by_default: bool,
    /// Disable browser fingerprinting
    pub anti_fingerprinting: bool,
    /// Enable HTTPS-only mode
    pub https_only: bool,
    /// Send Do Not Track header
    pub send_do_not_track: bool,
    /// History settings
    pub history: HistoryPrivacySettings,
    /// Cookie settings
    pub cookies: CookieSettings,
    /// Location settings
    pub location: LocationSettings,
    /// Camera and microphone settings
    pub media: MediaSettings,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        Self {
            privacy_level: PrivacyLevel::High,
            tracking_protection: true,
            block_third_party_cookies: true,
            clear_data_on_exit: false,
            private_by_default: false,
            anti_fingerprinting: true,
            https_only: false,
            send_do_not_track: true,
            history: HistoryPrivacySettings::default(),
            cookies: CookieSettings::default(),
            location: LocationSettings::default(),
            media: MediaSettings::default(),
        }
    }
}

/// History privacy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryPrivacySettings {
    /// Remember browsing history
    pub remember_history: bool,
    /// Remember form and search history
    pub remember_forms: bool,
    /// Remember download history
    pub remember_downloads: bool,
    /// Auto-clear history after
    pub auto_clear_after: Option<Duration>,
    /// Exclude private browsing from history
    pub exclude_private: bool,
    /// Include error pages in history
    pub include_errors: bool,
}

impl Default for HistoryPrivacySettings {
    fn default() -> Self {
        Self {
            remember_history: true,
            remember_forms: true,
            remember_downloads: true,
            auto_clear_after: None,
            exclude_private: true,
            include_errors: false,
        }
    }
}

/// Cookie settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CookiePolicy {
    AcceptAll,
    AcceptFirstParty,
    BlockAll,
    BlockThirdParty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieSettings {
    /// Cookie acceptance policy
    pub policy: CookiePolicy,
    /// Keep cookies until browser closes
    pub keep_until_close: bool,
    /// Delete stored cookies on exit
    pub delete_on_exit: bool,
    /// Allow site-specific exceptions
    pub site_exceptions: HashMap<String, CookiePolicy>,
}

impl Default for CookieSettings {
    fn default() -> Self {
        Self {
            policy: CookiePolicy::AcceptFirstParty,
            keep_until_close: false,
            delete_on_exit: false,
            site_exceptions: HashMap::new(),
        }
    }
}

/// Location settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationSettings {
    /// Allow sites to access location
    pub allow_location: bool,
    /// Ask before accessing location
    pub ask_before_access: bool,
    /// Site-specific permissions
    pub site_permissions: HashMap<String, bool>,
}

impl Default for LocationSettings {
    fn default() -> Self {
        Self {
            allow_location: false,
            ask_before_access: true,
            site_permissions: HashMap::new(),
        }
    }
}

/// Media (camera/microphone) settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaSettings {
    /// Allow camera access
    pub allow_camera: bool,
    /// Allow microphone access
    pub allow_microphone: bool,
    /// Ask before media access
    pub ask_before_access: bool,
    /// Site-specific permissions
    pub camera_permissions: HashMap<String, bool>,
    /// Site-specific microphone permissions
    pub microphone_permissions: HashMap<String, bool>,
}

impl Default for MediaSettings {
    fn default() -> Self {
        Self {
            allow_camera: false,
            allow_microphone: false,
            ask_before_access: true,
            camera_permissions: HashMap::new(),
            microphone_permissions: HashMap::new(),
        }
    }
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// DNS resolution mode
    pub dns_mode: DnsMode,
    /// Custom DNS servers
    pub custom_dns_servers: Vec<String>,
    /// Proxy settings
    pub proxy: ProxySettings,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Max concurrent connections per host
    pub max_connections_per_host: usize,
    /// Enable HTTP/2
    pub enable_http2: bool,
    /// Enable HTTP/3 (QUIC)
    pub enable_http3: bool,
    /// User agent string (empty for default randomization)
    pub custom_user_agent: Option<String>,
    /// Strip tracking parameters from URLs
    pub strip_tracking_params: bool,
    /// Disable referrer header
    pub disable_referrer: bool,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            dns_mode: DnsMode::LocalCache,
            custom_dns_servers: vec![
                "1.1.1.1".to_string(),
                "1.0.0.1".to_string(),
                "8.8.8.8".to_string(),
                "8.8.4.4".to_string(),
            ],
            proxy: ProxySettings::None,
            connection_timeout: Duration::from_secs(30),
            max_connections_per_host: 6,
            enable_http2: true,
            enable_http3: false,
            custom_user_agent: None,
            strip_tracking_params: true,
            disable_referrer: false,
        }
    }
}

/// Proxy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxySettings {
    /// No proxy
    None,
    /// System proxy settings
    System,
    /// Manual proxy configuration
    Manual {
        /// Proxy server URL
        server: String,
        /// Port number
        port: u16,
        /// Proxy username (optional)
        username: Option<String>,
        /// Proxy password (optional)
        password: Option<String>,
        /// Exclude these hosts from proxy
        exceptions: Vec<String>,
    },
}

/// Content settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSettings {
    /// Default font size
    pub default_font_size: u16,
    /// Minimum font size
    pub min_font_size: u16,
    /// Default font family
    pub default_font_family: String,
    /// Enable images
    pub enable_images: bool,
    /// Enable JavaScript
    pub enable_javascript: bool,
    /// Enable CSS animations
    pub enable_animations: bool,
    /// Enable WebGL
    pub enable_webgl: bool,
    /// Enable WebRTC
    pub enable_webrtc: bool,
    /// Pop-up policy
    pub popups: PopupPolicy,
    /// Advertisement settings
    pub ads: AdSettings,
    /// Website appearance
    pub appearance: WebsiteAppearance,
}

impl Default for ContentSettings {
    fn default() -> Self {
        Self {
            default_font_size: 16,
            min_font_size: 10,
            default_font_family: "system-ui".to_string(),
            enable_images: true,
            enable_javascript: true,
            enable_animations: true,
            enable_webgl: false, // Privacy-conscious default
            enable_webrtc: false, // Privacy-conscious default
            popups: PopupPolicy::Block,
            ads: AdSettings::default(),
            appearance: WebsiteAppearance::default(),
        }
    }
}

/// Pop-up policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PopupPolicy {
    Allow,
    Block,
    Ask,
}

/// Advertisement settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdSettings {
    /// Block advertisements
    pub block_ads: bool,
    /// Block trackers
    pub block_trackers: bool,
    /// Block social media widgets
    pub block_social: bool,
    /// Acceptable ads (non-intrusive)
    pub acceptable_ads: bool,
    /// Custom filter lists
    pub custom_filters: Vec<String>,
}

impl Default for AdSettings {
    fn default() -> Self {
        Self {
            block_ads: true,
            block_trackers: true,
            block_social: false,
            acceptable_ads: false,
            custom_filters: Vec::new(),
        }
    }
}

/// Website appearance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebsiteAppearance {
    /// Default theme
    pub theme: WebsiteTheme,
    /// Force dark mode
    pub force_dark_mode: bool,
    /// High contrast mode
    pub high_contrast: bool,
    /// Reduce motion
    pub reduce_motion: bool,
    /// Custom CSS
    pub custom_css: Option<String>,
}

impl Default for WebsiteAppearance {
    fn default() -> Self {
        Self {
            theme: WebsiteTheme::System,
            force_dark_mode: false,
            high_contrast: false,
            reduce_motion: false,
            custom_css: None,
        }
    }
}

/// Website theme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebsiteTheme {
    System,
    Light,
    Dark,
}

/// User interface settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UISettings {
    /// Application theme
    pub theme: AppTheme,
    /// Show bookmarks bar
    pub show_bookmarks_bar: bool,
    /// Show downloads bar
    pub show_downloads_bar: bool,
    /// Show tab bar
    pub show_tab_bar: bool,
    /// Show navigation bar
    pub show_nav_bar: bool,
    /// Tab behavior
    pub tabs: TabSettings,
    /// Window settings
    pub window: WindowSettings,
    /// Keyboard shortcuts
    pub shortcuts: KeyboardSettings,
    /// Zoom settings
    pub zoom: ZoomSettings,
}

impl Default for UISettings {
    fn default() -> Self {
        Self {
            theme: AppTheme::Dark,
            show_bookmarks_bar: true,
            show_downloads_bar: false,
            show_tab_bar: true,
            show_nav_bar: true,
            tabs: TabSettings::default(),
            window: WindowSettings::default(),
            shortcuts: KeyboardSettings::default(),
            zoom: ZoomSettings::default(),
        }
    }
}

/// Application theme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppTheme {
    Light,
    Dark,
    System,
}

/// Tab settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabSettings {
    /// New tabs open after current tab
    pub new_tabs_after_current: bool,
    /// Close tabs with middle click
    pub close_with_middle_click: bool,
    /// Double-click tab bar to open new tab
    pub double_click_new_tab: bool,
    /// Show tab previews
    pub show_previews: bool,
    /// Maximum number of tabs before scrolling
    pub max_tabs_before_scroll: usize,
    /// Warn when closing multiple tabs
    pub warn_close_multiple: bool,
}

impl Default for TabSettings {
    fn default() -> Self {
        Self {
            new_tabs_after_current: true,
            close_with_middle_click: true,
            double_click_new_tab: true,
            show_previews: true,
            max_tabs_before_scroll: 10,
            warn_close_multiple: true,
        }
    }
}

/// Window settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSettings {
    /// Remember window size and position
    pub remember_window_state: bool,
    /// Start maximized
    pub start_maximized: bool,
    /// Always on top
    pub always_on_top: bool,
    /// Minimize to tray
    pub minimize_to_tray: bool,
    /// Show in taskbar when minimized
    pub show_in_taskbar: bool,
    /// Window width
    pub default_width: u32,
    /// Window height
    pub default_height: u32,
}

impl Default for WindowSettings {
    fn default() -> Self {
        Self {
            remember_window_state: true,
            start_maximized: false,
            always_on_top: false,
            minimize_to_tray: false,
            show_in_taskbar: true,
            default_width: 1200,
            default_height: 800,
        }
    }
}

/// Keyboard settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyboardSettings {
    /// Enable keyboard shortcuts
    pub enable_shortcuts: bool,
    /// Custom shortcuts
    pub custom_shortcuts: HashMap<String, String>,
}

impl Default for KeyboardSettings {
    fn default() -> Self {
        Self {
            enable_shortcuts: true,
            custom_shortcuts: HashMap::new(),
        }
    }
}

/// Zoom settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoomSettings {
    /// Default zoom level (percentage)
    pub default_zoom: u16,
    /// Minimum zoom level
    pub min_zoom: u16,
    /// Maximum zoom level
    pub max_zoom: u16,
    /// Zoom step size
    pub zoom_step: u16,
    /// Text-only zoom
    pub text_only: bool,
}

impl Default for ZoomSettings {
    fn default() -> Self {
        Self {
            default_zoom: 100,
            min_zoom: 50,
            max_zoom: 200,
            zoom_step: 25,
            text_only: false,
        }
    }
}

/// Performance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    /// Enable hardware acceleration
    pub hardware_acceleration: bool,
    /// Maximum memory usage (MB)
    pub max_memory_mb: usize,
    /// Maximum number of processes
    pub max_processes: usize,
    /// Process model
    pub process_model: ProcessModel,
    /// Cache settings
    pub cache: CacheSettings,
    /// Preload settings
    pub preload: PreloadSettings,
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            hardware_acceleration: true,
            max_memory_mb: 2048,
            max_processes: 8,
            process_model: ProcessModel::ProcessPerSite,
            cache: CacheSettings::default(),
            preload: PreloadSettings::default(),
        }
    }
}

/// Process model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessModel {
    /// Single process for all tabs
    SingleProcess,
    /// One process per site
    ProcessPerSite,
    /// One process per tab
    ProcessPerTab,
}

/// Cache settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSettings {
    /// Enable disk cache
    pub enable_disk_cache: bool,
    /// Maximum cache size (MB)
    pub max_cache_size_mb: usize,
    /// Cache location (empty for default)
    pub cache_location: Option<String>,
    /// Clear cache on exit
    pub clear_on_exit: bool,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            enable_disk_cache: true,
            max_cache_size_mb: 1024,
            cache_location: None,
            clear_on_exit: false,
        }
    }
}

/// Preload settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreloadSettings {
    /// Preload top sites on startup
    pub preload_top_sites: bool,
    /// Preload search suggestions
    pub preload_search_suggestions: bool,
    /// Preload new tab page
    pub preload_new_tab: bool,
    /// Maximum preloaded pages
    pub max_preloaded_pages: usize,
}

impl Default for PreloadSettings {
    fn default() -> Self {
        Self {
            preload_top_sites: false, // Privacy-conscious default
            preload_search_suggestions: false, // Privacy-conscious default
            preload_new_tab: true,
            max_preloaded_pages: 3,
        }
    }
}

/// Extension settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionSettings {
    /// Enable extensions
    pub enable_extensions: bool,
    /// Allow extensions in private browsing
    pub allow_private_extensions: bool,
    /// Automatically update extensions
    pub auto_update: bool,
    /// Allowed extension sources
    pub allowed_sources: Vec<String>,
    /// Blocked extensions
    pub blocked_extensions: Vec<String>,
}

impl Default for ExtensionSettings {
    fn default() -> Self {
        Self {
            enable_extensions: true,
            allow_private_extensions: false,
            auto_update: true,
            allowed_sources: vec!["https://addons.mozilla.org".to_string()],
            blocked_extensions: Vec::new(),
        }
    }
}

/// Advanced settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedSettings {
    /// Enable experimental features
    pub experimental_features: bool,
    /// Enable developer tools
    pub enable_devtools: bool,
    /// User agent override
    pub user_agent_override: Option<String>,
    /// Custom headers
    pub custom_headers: HashMap<String, String>,
    /// Certificate settings
    pub certificates: CertificateSettings,
    /// Security settings
    pub security: SecuritySettings,
}

impl Default for AdvancedSettings {
    fn default() -> Self {
        Self {
            experimental_features: false,
            enable_devtools: true,
            user_agent_override: None,
            custom_headers: HashMap::new(),
            certificates: CertificateSettings::default(),
            security: SecuritySettings::default(),
        }
    }
}

/// Certificate settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSettings {
    /// Trust system certificates
    pub trust_system: bool,
    /// Trust user certificates
    pub trust_user: bool,
    /// Certificate verification mode
    pub verification_mode: CertificateVerification,
}

impl Default for CertificateSettings {
    fn default() -> Self {
        Self {
            trust_system: true,
            trust_user: true,
            verification_mode: CertificateVerification::Strict,
        }
    }
}

/// Certificate verification modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertificateVerification {
    /// Strict certificate verification
    Strict,
    /// Allow expired certificates with warning
    AllowExpired,
    /// Allow self-signed certificates
    AllowSelfSigned,
    /// Disable certificate verification (not recommended)
    Disabled,
}

/// Advanced security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Enable mixed content blocking
    pub block_mixed_content: bool,
    /// Enable certificate transparency
    pub certificate_transparency: bool,
    /// Enable HSTS preloading
    pub hsts_preload: bool,
    /// Enable safe browsing
    pub safe_browsing: bool,
    /// Allow insecure protocols
    pub allow_insecure_protocols: bool,
    /// CSP enforcement level
    pub csp_enforcement: CspEnforcement,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            block_mixed_content: true,
            certificate_transparency: true,
            hsts_preload: true,
            safe_browsing: true,
            allow_insecure_protocols: false,
            csp_enforcement: CspEnforcement::Strict,
        }
    }
}

/// Content Security Policy enforcement levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CspEnforcement {
    /// No CSP enforcement
    None,
    /// Report-only mode
    ReportOnly,
    /// Strict enforcement
    Strict,
}

/// Settings manager
#[derive(Debug)]
pub struct SettingsManager {
    settings: BrowserSettings,
    settings_file: std::path::PathBuf,
}

impl SettingsManager {
    /// Create new settings manager
    pub fn new() -> Result<Self, SettingsError> {
        let settings_dir = dirs::config_dir()
            .ok_or(SettingsError::ConfigDirNotFound)?
            .join("citadel-browser");

        std::fs::create_dir_all(&settings_dir)?;

        let settings_file = settings_dir.join("settings.json");

        let settings = if settings_file.exists() {
            Self::load_settings(&settings_file)?
        } else {
            BrowserSettings::default()
        };

        Ok(Self {
            settings,
            settings_file,
        })
    }

    /// Load settings from file
    fn load_settings(path: &std::path::Path) -> Result<BrowserSettings, SettingsError> {
        let content = std::fs::read_to_string(path)?;
        let settings: BrowserSettings = serde_json::from_str(&content)?;
        Ok(settings)
    }

    /// Save settings to file
    pub fn save_settings(&self) -> Result<(), SettingsError> {
        let content = serde_json::to_string_pretty(&self.settings)?;
        std::fs::write(&self.settings_file, content)?;
        Ok(())
    }

    /// Get current settings
    pub fn get_settings(&self) -> &BrowserSettings {
        &self.settings
    }

    /// Update settings
    pub fn update_settings<F>(&mut self, updater: F) -> Result<(), SettingsError>
    where
        F: FnOnce(&mut BrowserSettings),
    {
        updater(&mut self.settings);
        self.save_settings()
    }

    /// Reset to default settings
    pub fn reset_to_default(&mut self) -> Result<(), SettingsError> {
        self.settings = BrowserSettings::default();
        self.save_settings()
    }

    /// Export settings
    pub fn export_settings(&self, path: &std::path::Path) -> Result<(), SettingsError> {
        let content = serde_json::to_string_pretty(&self.settings)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Import settings
    pub fn import_settings(&mut self, path: &std::path::Path) -> Result<(), SettingsError> {
        let content = std::fs::read_to_string(path)?;
        self.settings = serde_json::from_str(&content)?;
        self.save_settings()
    }

    /// Validate settings
    pub fn validate_settings(&self) -> Vec<SettingsWarning> {
        let mut warnings = Vec::new();

        // Check privacy settings
        if !self.settings.privacy.tracking_protection {
            warnings.push(SettingsWarning::TrackingProtectionDisabled);
        }

        if !self.settings.privacy.https_only {
            warnings.push(SettingsWarning::HttpsOnlyDisabled);
        }

        // Check security settings
        if !self.settings.advanced.security.block_mixed_content {
            warnings.push(SettingsWarning::MixedContentAllowed);
        }

        if !self.settings.advanced.security.safe_browsing {
            warnings.push(SettingsWarning::SafeBrowsingDisabled);
        }

        // Check performance settings
        if self.settings.performance.max_memory_mb < 512 {
            warnings.push(SettingsWarning::LowMemoryLimit);
        }

        // Check content settings
        if !self.settings.content.enable_javascript {
            warnings.push(SettingsWarning::JavascriptDisabled);
        }

        warnings
    }
}

/// Settings errors
#[derive(Debug, Clone)]
pub enum SettingsError {
    ConfigDirNotFound,
    IoError(String),
    SerializationError(String),
    FileNotFound,
}

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettingsError::ConfigDirNotFound => write!(f, "Configuration directory not found"),
            SettingsError::IoError(msg) => write!(f, "IO error: {}", msg),
            SettingsError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            SettingsError::FileNotFound => write!(f, "Settings file not found"),
        }
    }
}

impl std::error::Error for SettingsError {}

impl From<std::io::Error> for SettingsError {
    fn from(err: std::io::Error) -> Self {
        SettingsError::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for SettingsError {
    fn from(err: serde_json::Error) -> Self {
        SettingsError::SerializationError(err.to_string())
    }
}

/// Settings warnings
#[derive(Debug, Clone)]
pub enum SettingsWarning {
    TrackingProtectionDisabled,
    HttpsOnlyDisabled,
    MixedContentAllowed,
    SafeBrowsingDisabled,
    LowMemoryLimit,
    JavascriptDisabled,
    InsecureCertificateSettings,
}

impl std::fmt::Display for SettingsWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettingsWarning::TrackingProtectionDisabled => {
                write!(f, "Tracking protection is disabled - your privacy may be at risk")
            }
            SettingsWarning::HttpsOnlyDisabled => {
                write!(f, "HTTPS-only mode is disabled - connections may be insecure")
            }
            SettingsWarning::MixedContentAllowed => {
                write!(f, "Mixed content blocking is disabled - security may be compromised")
            }
            SettingsWarning::SafeBrowsingDisabled => {
                write!(f, "Safe browsing is disabled - malicious sites may not be blocked")
            }
            SettingsWarning::LowMemoryLimit => {
                write!(f, "Memory limit is very low - performance may be affected")
            }
            SettingsWarning::JavascriptDisabled => {
                write!(f, "JavaScript is disabled - many websites may not work correctly")
            }
            SettingsWarning::InsecureCertificateSettings => {
                write!(f, "Certificate verification is not strict - security may be compromised")
            }
        }
    }
}