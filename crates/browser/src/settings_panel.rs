//! Settings and preferences panel for Citadel Browser
//!
//! This module provides comprehensive configuration options for privacy,
//! security, appearance, and browsing behavior.

use iced::{
    widget::{button, container, text, text_input, scrollable, Space, Column, Row,
             checkbox, slider, pick_list, tooltip, horizontal_rule, vertical_rule,
             toggler},
    Element, Length, Color, Alignment, theme, Command,
};
use citadel_networking::{NetworkConfig, PrivacyLevel, DnsProvider};
use crate::app::{Message, ZoomLevel};
use crate::ui_modern::{colors, typography, spacing, radius, GlassStyle, CardStyle};
use crate::theme::{CitadelTheme, ThemeManager};

/// Settings categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsCategory {
    Privacy,
    Security,
    Appearance,
    Browsing,
    Advanced,
    About,
}

impl SettingsCategory {
    const ALL: [Self; 6] = [
        Self::Privacy,
        Self::Security,
        Self::Appearance,
        Self::Browsing,
        Self::Advanced,
        Self::About,
    ];

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Privacy => "Privacy",
            Self::Security => "Security",
            Self::Appearance => "Appearance",
            Self::Browsing => "Browsing",
            Self::Advanced => "Advanced",
            Self::About => "About",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Privacy => "🛡️",
            Self::Security => "🔒",
            Self::Appearance => "🎨",
            Self::Browsing => "🌐",
            Self::Advanced => "⚙️",
            Self::About => "ℹ️",
        }
    }
}

/// Settings panel state
#[derive(Debug, Clone)]
pub struct SettingsPanel {
    /// Currently selected category
    active_category: SettingsCategory,
    /// Whether settings panel is visible
    visible: bool,
    /// Search query for settings
    search_query: String,

    // Privacy settings
    privacy_level: PrivacyLevel,
    block_trackers: bool,
    anti_fingerprinting: bool,
    private_dns: bool,
    dns_provider: DnsProvider,
    clear_cookies_on_exit: bool,
    block_third_party_cookies: bool,

    // Security settings
    malware_protection: bool,
    phishing_protection: bool,
    safe_browsing: bool,
    certificate_checking: bool,
    mixed_content_blocking: bool,

    // Appearance settings
    theme: CitadelTheme,
    font_size: u16,
    zoom_default: ZoomLevel,
    show_bookmarks_bar: bool,
    show_downloads_bar: bool,
    compact_mode: bool,
    animations_enabled: bool,

    // Browsing settings
    search_engine: SearchEngine,
    homepage_type: HomepageType,
    custom_homepage: String,
    restore_last_session: bool,
    auto_fill: bool,
    password_manager: bool,

    // Advanced settings
    developer_mode: bool,
    experimental_features: bool,
    hardware_acceleration: bool,
    memory_saver: bool,
    background_sync: bool,
    log_level: LogLevel,
}

/// Available search engines
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchEngine {
    DuckDuckGo,
    Startpage,
    Brave,
    Qwant,
    Swisscows,
    Custom,
}

impl SearchEngine {
    const ALL: [Self; 6] = [
        Self::DuckDuckGo,
        Self::Startpage,
        Self::Brave,
        Self::Qwant,
        Self::Swisscows,
        Self::Custom,
    ];

    pub fn display_name(self) -> &'static str {
        match self {
            Self::DuckDuckGo => "DuckDuckGo",
            Self::Startpage => "Startpage",
            Self::Brave => "Brave Search",
            Self::Qwant => "Qwant",
            Self::Swisscows => "Swisscows",
            Self::Custom => "Custom",
        }
    }

    pub fn search_url(self, query: &str) -> String {
        match self {
            Self::DuckDuckGo => format!("https://duckduckgo.com/?q={}", urlencoding::encode(query)),
            Self::Startpage => format!("https://www.startpage.com/do/search?query={}", urlencoding::encode(query)),
            Self::Brave => format!("https://search.brave.com/search?q={}", urlencoding::encode(query)),
            Self::Qwant => format!("https://www.qwant.com/?q={}", urlencoding::encode(query)),
            Self::Swisscows => format!("https://swisscows.com/web?query={}", urlencoding::encode(query)),
            Self::Custom => query.to_string(), // User should provide full URL
        }
    }
}

/// Homepage type options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomepageType {
    NewTab,
    Blank,
    Custom,
    HomePage,
}

impl HomepageType {
    const ALL: [Self; 4] = [Self::NewTab, Self::Blank, Self::Custom, Self::HomePage];

    pub fn display_name(self) -> &'static str {
        match self {
            Self::NewTab => "New Tab",
            Self::Blank => "Blank Page",
            Self::Custom => "Custom URL",
            Self::HomePage => "Home Page",
        }
    }
}

/// Log levels for debugging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    const ALL: [Self; 5] = [Self::Error, Self::Warn, Self::Info, Self::Debug, Self::Trace];

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Error => "Error",
            Self::Warn => "Warning",
            Self::Info => "Info",
            Self::Debug => "Debug",
            Self::Trace => "Trace",
        }
    }
}

/// Settings messages
#[derive(Debug, Clone)]
pub enum SettingsMessage {
    /// Panel visibility
    ShowSettings,
    HideSettings,
    ToggleSettings,

    /// Category navigation
    SelectCategory(SettingsCategory),
    SearchSettings(String),

    // Privacy settings
    SetPrivacyLevel(PrivacyLevel),
    ToggleBlockTrackers(bool),
    ToggleAntiFingerprinting(bool),
    TogglePrivateDns(bool),
    SetDnsProvider(DnsProvider),
    ToggleClearCookiesOnExit(bool),
    ToggleBlockThirdPartyCookies(bool),

    // Security settings
    ToggleMalwareProtection(bool),
    TogglePhishingProtection(bool),
    ToggleSafeBrowsing(bool),
    ToggleCertificateChecking(bool),
    ToggleMixedContentBlocking(bool),

    // Appearance settings
    SetTheme(CitadelTheme),
    SetFontSize(u16),
    SetDefaultZoom(ZoomLevel),
    ToggleBookmarksBar(bool),
    ToggleDownloadsBar(bool),
    ToggleCompactMode(bool),
    ToggleAnimations(bool),

    // Browsing settings
    SetSearchEngine(SearchEngine),
    SetHomepageType(HomepageType),
    SetCustomHomepage(String),
    ToggleRestoreSession(bool),
    ToggleAutoFill(bool),
    TogglePasswordManager(bool),

    // Advanced settings
    ToggleDeveloperMode(bool),
    ToggleExperimentalFeatures(bool),
    ToggleHardwareAcceleration(bool),
    ToggleMemorySaver(bool),
    ToggleBackgroundSync(bool),
    SetLogLevel(LogLevel),

    // Actions
    ResetToDefaults,
    ExportSettings,
    ImportSettings,
    ClearBrowsingData,
}

impl SettingsPanel {
    /// Create a new settings panel with default values
    pub fn new() -> Self {
        Self {
            active_category: SettingsCategory::Privacy,
            visible: false,
            search_query: String::new(),

            // Privacy defaults
            privacy_level: PrivacyLevel::High,
            block_trackers: true,
            anti_fingerprinting: true,
            private_dns: true,
            dns_provider: DnsProvider::Cloudflare,
            clear_cookies_on_exit: true,
            block_third_party_cookies: true,

            // Security defaults
            malware_protection: true,
            phishing_protection: true,
            safe_browsing: true,
            certificate_checking: true,
            mixed_content_blocking: true,

            // Appearance defaults
            theme: CitadelTheme::Dark,
            font_size: 16,
            zoom_default: ZoomLevel::Percent100,
            show_bookmarks_bar: false,
            show_downloads_bar: false,
            compact_mode: false,
            animations_enabled: true,

            // Browsing defaults
            search_engine: SearchEngine::DuckDuckGo,
            homepage_type: HomepageType::NewTab,
            custom_homepage: String::new(),
            restore_last_session: true,
            auto_fill: false,
            password_manager: false,

            // Advanced defaults
            developer_mode: false,
            experimental_features: false,
            hardware_acceleration: true,
            memory_saver: true,
            background_sync: false,
            log_level: LogLevel::Info,
        }
    }

    /// Check if settings panel is visible
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Update settings based on message
    pub fn update(&mut self, message: SettingsMessage) -> Command<Message> {
        match message {
            SettingsMessage::ShowSettings => self.visible = true,
            SettingsMessage::HideSettings => self.visible = false,
            SettingsMessage::ToggleSettings => self.visible = !self.visible,

            SettingsMessage::SelectCategory(category) => self.active_category = category,
            SettingsMessage::SearchSettings(query) => self.search_query = query,

            // Privacy settings
            SettingsMessage::SetPrivacyLevel(level) => self.privacy_level = level,
            SettingsMessage::ToggleBlockTrackers(enabled) => self.block_trackers = enabled,
            SettingsMessage::ToggleAntiFingerprinting(enabled) => self.anti_fingerprinting = enabled,
            SettingsMessage::TogglePrivateDns(enabled) => self.private_dns = enabled,
            SettingsMessage::SetDnsProvider(provider) => self.dns_provider = provider,
            SettingsMessage::ToggleClearCookiesOnExit(enabled) => self.clear_cookies_on_exit = enabled,
            SettingsMessage::ToggleBlockThirdPartyCookies(enabled) => self.block_third_party_cookies = enabled,

            // Security settings
            SettingsMessage::ToggleMalwareProtection(enabled) => self.malware_protection = enabled,
            SettingsMessage::TogglePhishingProtection(enabled) => self.phishing_protection = enabled,
            SettingsMessage::ToggleSafeBrowsing(enabled) => self.safe_browsing = enabled,
            SettingsMessage::ToggleCertificateChecking(enabled) => self.certificate_checking = enabled,
            SettingsMessage::ToggleMixedContentBlocking(enabled) => self.mixed_content_blocking = enabled,

            // Appearance settings
            SettingsMessage::SetTheme(theme) => self.theme = theme,
            SettingsMessage::SetFontSize(size) => self.font_size = size,
            SettingsMessage::SetDefaultZoom(zoom) => self.zoom_default = zoom,
            SettingsMessage::ToggleBookmarksBar(enabled) => self.show_bookmarks_bar = enabled,
            SettingsMessage::ToggleDownloadsBar(enabled) => self.show_downloads_bar = enabled,
            SettingsMessage::ToggleCompactMode(enabled) => self.compact_mode = enabled,
            SettingsMessage::ToggleAnimations(enabled) => self.animations_enabled = enabled,

            // Browsing settings
            SettingsMessage::SetSearchEngine(engine) => self.search_engine = engine,
            SettingsMessage::SetHomepageType(homepage_type) => self.homepage_type = homepage_type,
            SettingsMessage::SetCustomHomepage(url) => self.custom_homepage = url,
            SettingsMessage::ToggleRestoreSession(enabled) => self.restore_last_session = enabled,
            SettingsMessage::ToggleAutoFill(enabled) => self.auto_fill = enabled,
            SettingsMessage::TogglePasswordManager(enabled) => self.password_manager = enabled,

            // Advanced settings
            SettingsMessage::ToggleDeveloperMode(enabled) => self.developer_mode = enabled,
            SettingsMessage::ToggleExperimentalFeatures(enabled) => self.experimental_features = enabled,
            SettingsMessage::ToggleHardwareAcceleration(enabled) => self.hardware_acceleration = enabled,
            SettingsMessage::ToggleMemorySaver(enabled) => self.memory_saver = enabled,
            SettingsMessage::ToggleBackgroundSync(enabled) => self.background_sync = enabled,
            SettingsMessage::SetLogLevel(level) => self.log_level = level,

            // Actions (would typically trigger additional commands)
            SettingsMessage::ResetToDefaults => *self = Self::new(),
            SettingsMessage::ExportSettings => {
                // TODO: Export settings to file
            }
            SettingsMessage::ImportSettings => {
                // TODO: Import settings from file
            }
            SettingsMessage::ClearBrowsingData => {
                // TODO: Clear browsing data
            }
        }
        Command::none()
    }

    /// Create the settings panel view
    pub fn view(&self) -> Element<Message> {
        let main_content = Row::new()
            .push(self.create_sidebar())
            .push(vertical_rule(1))
            .push(self.create_content_area())
            .spacing(0);

        let panel = Column::new()
            .push(
                self.create_header()
            )
            .push(horizontal_rule(1))
            .push(
                container(main_content)
                    .width(Length::Fill)
                    .height(Length::Fill)
            )
            .spacing(0);

        container(panel)
            .width(Length::Fill)
            .height(Length::Fill)
            .max_width(1000)
            .max_height(700)
            .style(theme::Container::Custom(Box::new(GlassStyle)))
            .center_x()
            .center_y()
            .into()
    }

    /// Create settings panel header
    fn create_header(&self) -> Element<Message> {
        let header = Row::new()
            .push(
                text("⚙️ Settings")
                    .size(typography::H2)
                    .style(colors::TEXT_PRIMARY)
            )
            .push(Space::with_width(Length::Fill))
            .push(
                button(text("×").size(24))
                    .padding(spacing::SM)
                    .style(theme::Button::Text)
                    .on_press(Message::ToggleSettings)
            )
            .align_items(Alignment::Center)
            .padding([spacing::MD, spacing::XL]);

        container(header)
            .width(Length::Fill)
            .padding(spacing::MD)
            .into()
    }

    /// Create settings sidebar with categories
    fn create_sidebar(&self) -> Element<Message> {
        let categories = Column::new()
            .spacing(spacing::XS);

        let mut categories = categories;

        for category in SettingsCategory::ALL {
            let category_button = button(
                Row::new()
                    .push(text(category.icon()).size(16))
                    .push(Space::with_width(spacing::SM))
                    .push(text(category.display_name()).size(typography::SMALL))
                    .align_items(Alignment::Center)
            )
            .padding([spacing::SM, spacing::MD])
            .width(Length::Fill)
            .style(if self.active_category == category {
                theme::Button::Primary
            } else {
                theme::Button::Text
            })
            .on_press(Message::Settings(crate::app::SettingsMessage::SelectCategory(category)));

            categories = categories.push(category_button);
        }

        container(
            scrollable(categories)
                .width(Length::Fixed(200.0))
        )
        .width(Length::Fixed(200.0))
        .height(Length::Fill)
        .padding(spacing::MD)
        .into()
    }

    /// Create content area for selected category
    fn create_content_area(&self) -> Element<Message> {
        let content = match self.active_category {
            SettingsCategory::Privacy => self.create_privacy_settings(),
            SettingsCategory::Security => self.create_security_settings(),
            SettingsCategory::Appearance => self.create_appearance_settings(),
            SettingsCategory::Browsing => self.create_browsing_settings(),
            SettingsCategory::Advanced => self.create_advanced_settings(),
            SettingsCategory::About => self.create_about_section(),
        };

        container(
            scrollable(content)
                .width(Length::Fill)
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(spacing::LG)
        .into()
    }

    /// Create privacy settings panel
    fn create_privacy_settings(&self) -> Element<Message> {
        let content = Column::new()
            .push(
                self.create_section_header("Privacy Settings", "Configure your privacy preferences")
            )
            .push(Space::with_height(spacing::LG))
            .push(
                self.create_privacy_level_selector()
            )
            .push(Space::with_height(spacing::XL))
            .push(
                self.create_section_header("Tracking Protection", "Block trackers and protect your privacy")
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Block Trackers", "Prevent websites from tracking your activity",
                    self.block_trackers, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleBlockTrackers(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Anti-Fingerprinting", "Protect against browser fingerprinting",
                    self.anti_fingerprinting, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleAntiFingerprinting(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Block Third-Party Cookies", "Prevent third-party cookies",
                    self.block_third_party_cookies, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleBlockThirdPartyCookies(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Clear Cookies on Exit", "Automatically clear cookies when closing browser",
                    self.clear_cookies_on_exit, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleClearCookiesOnExit(enabled)))
            )
            .push(Space::with_height(spacing::XL))
            .push(
                self.create_section_header("Private DNS", "Use secure DNS resolution")
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Enable Private DNS", "Use encrypted DNS",
                    self.private_dns, |enabled| Message::Settings(crate::app::SettingsMessage::TogglePrivateDns(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_dns_provider_selector()
            );

        container(content)
            .width(Length::Fill)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .padding(spacing::LG)
            .into()
    }

    /// Create privacy level selector
    fn create_privacy_level_selector(&self) -> Element<Message> {
        let mut levels = Row::new().spacing(spacing::MD);

        for level in [PrivacyLevel::Maximum, PrivacyLevel::High, PrivacyLevel::Balanced] {
            let level_name = match level {
                PrivacyLevel::Maximum => "Maximum",
                PrivacyLevel::High => "High",
                PrivacyLevel::Balanced => "Balanced",
                PrivacyLevel::Custom => "Custom",
            };

            let level_desc = match level {
                PrivacyLevel::Maximum => "Strictest privacy settings",
                PrivacyLevel::High => "Enhanced privacy protection",
                PrivacyLevel::Balanced => "Balanced privacy and functionality",
                PrivacyLevel::Custom => "Custom configuration",
            };

            let is_selected = self.privacy_level == level;

            let level_card = container(
                Column::new()
                    .push(text(level_name).size(typography::BODY).style(if is_selected { colors::TEXT_PRIMARY } else { colors::TEXT_SECONDARY }))
                    .push(Space::with_height(spacing::XS))
                    .push(text(level_desc).size(typography::CAPTION).style(colors::TEXT_MUTED))
                    .align_items(Alignment::Center)
            )
            .padding(spacing::MD)
            .width(Length::Fill)
            .style(theme::Container::Custom(Box::new(
                crate::ui_modern::PrivacyIndicatorStyle { privacy_level: level }
            )))
            .center_x();

            let button = button(level_card)
                .padding(0)
                .width(Length::Fill)
                .style(if is_selected { theme::Button::Primary } else { theme::Button::Secondary })
                .on_press(Message::Settings(crate::app::SettingsMessage::SetPrivacyLevel(level)));

            levels = levels.push(button);
        }

        container(levels)
            .width(Length::Fill)
            .into()
    }

    /// Create DNS provider selector
    fn create_dns_provider_selector(&self) -> Element<Message> {
        let providers = vec![
            DnsProvider::Cloudflare,
            DnsProvider::Google,
            DnsProvider::Quad9,
            DnsProvider::OpenDNS,
        ];

        let selector = pick_list(
            providers,
            Some(self.dns_provider.clone()),
            |provider| Message::Settings(crate::app::SettingsMessage::SetDnsProvider(provider)),
        )
        .padding(spacing::SM)
        .width(Length::Fixed(200.0));

        Row::new()
            .push(text("DNS Provider:").size(typography::BODY).style(colors::TEXT_SECONDARY))
            .push(Space::with_width(spacing::MD))
            .push(selector)
            .align_items(Alignment::Center)
            .into()
    }

    /// Create security settings panel
    fn create_security_settings(&self) -> Element<Message> {
        let content = Column::new()
            .push(
                self.create_section_header("Security Settings", "Configure security protections")
            )
            .push(Space::with_height(spacing::LG))
            .push(
                self.create_toggle_setting("Malware Protection", "Block malicious software",
                    self.malware_protection, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleMalwareProtection(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Phishing Protection", "Block phishing attempts",
                    self.phishing_protection, |enabled| Message::Settings(crate::app::SettingsMessage::TogglePhishingProtection(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Safe Browsing", "Warn about dangerous sites",
                    self.safe_browsing, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleSafeBrowsing(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Certificate Checking", "Verify SSL certificates",
                    self.certificate_checking, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleCertificateChecking(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Block Mixed Content", "Prevent insecure content on secure pages",
                    self.mixed_content_blocking, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleMixedContentBlocking(enabled)))
            );

        container(content)
            .width(Length::Fill)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .padding(spacing::LG)
            .into()
    }

    /// Create appearance settings panel
    fn create_appearance_settings(&self) -> Element<Message> {
        let content = Column::new()
            .push(
                self.create_section_header("Appearance", "Customize browser appearance")
            )
            .push(Space::with_height(spacing::LG))
            .push(
                self.create_theme_selector()
            )
            .push(Space::with_height(spacing::XL))
            .push(
                self.create_slider_setting("Font Size", "Adjust default font size",
                    12..=24, self.font_size, |size| Message::Settings(crate::app::SettingsMessage::SetFontSize(size)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_zoom_selector()
            )
            .push(Space::with_height(spacing::XL))
            .push(
                self.create_section_header("Interface", "Configure browser interface")
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Show Bookmarks Bar", "Display bookmarks toolbar",
                    self.show_bookmarks_bar, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleBookmarksBar(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Show Downloads Bar", "Display downloads toolbar",
                    self.show_downloads_bar, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleDownloadsBar(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Compact Mode", "Use compact interface layout",
                    self.compact_mode, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleCompactMode(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Enable Animations", "Show interface animations",
                    self.animations_enabled, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleAnimations(enabled)))
            );

        container(content)
            .width(Length::Fill)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .padding(spacing::LG)
            .into()
    }

    /// Create theme selector
    fn create_theme_selector(&self) -> Element<Message> {
        let themes = vec![
            CitadelTheme::Dark,
            CitadelTheme::Light,
            CitadelTheme::HighContrast,
            CitadelTheme::Sepia,
        ];

        let theme_names: Vec<&str> = themes.iter().map(|t| {
            match t {
                CitadelTheme::Dark => "Dark",
                CitadelTheme::Light => "Light",
                CitadelTheme::HighContrast => "High Contrast",
                CitadelTheme::Sepia => "Sepia",
                CitadelTheme::Custom { .. } => "Custom",
            }
        }).collect();

        Row::new()
            .push(text("Theme:").size(typography::BODY).style(colors::TEXT_SECONDARY))
            .push(Space::with_width(spacing::MD))
            .push(
                pick_list(
                    theme_names,
                    Some(match self.theme {
                        CitadelTheme::Dark => "Dark",
                        CitadelTheme::Light => "Light",
                        CitadelTheme::HighContrast => "High Contrast",
                        CitadelTheme::Sepia => "Sepia",
                        CitadelTheme::Custom { .. } => "Custom",
                    }),
                    |name| {
                        let theme = match name {
                            "Dark" => CitadelTheme::Dark,
                            "Light" => CitadelTheme::Light,
                            "High Contrast" => CitadelTheme::HighContrast,
                            "Sepia" => CitadelTheme::Sepia,
                            _ => CitadelTheme::Dark,
                        };
                        Message::Settings(crate::app::SettingsMessage::SetTheme(theme))
                    },
                )
                .padding(spacing::SM)
                .width(Length::Fixed(200.0))
            )
            .align_items(Alignment::Center)
            .into()
    }

    /// Create zoom level selector
    fn create_zoom_selector(&self) -> Element<Message> {
        let zoom_levels = vec![
            ZoomLevel::Percent50,
            ZoomLevel::Percent75,
            ZoomLevel::Percent100,
            ZoomLevel::Percent125,
            ZoomLevel::Percent150,
            ZoomLevel::Percent200,
        ];

        let zoom_names: Vec<String> = zoom_levels.iter().map(|z| format!("{}%", z.as_percentage())).collect();

        Row::new()
            .push(text("Default Zoom:").size(typography::BODY).style(colors::TEXT_SECONDARY))
            .push(Space::with_width(spacing::MD))
            .push(
                pick_list(
                    zoom_names,
                    Some(format!("{}%", self.zoom_default.as_percentage())),
                    |name| {
                        let percent: u16 = name.trim_end_matches('%').parse().unwrap_or(100);
                        let zoom = match percent {
                            50 => ZoomLevel::Percent50,
                            75 => ZoomLevel::Percent75,
                            100 => ZoomLevel::Percent100,
                            125 => ZoomLevel::Percent125,
                            150 => ZoomLevel::Percent150,
                            200 => ZoomLevel::Percent200,
                            _ => ZoomLevel::Percent100,
                        };
                        Message::Settings(crate::app::SettingsMessage::SetDefaultZoom(zoom.as_factor()))
                    },
                )
                .padding(spacing::SM)
                .width(Length::Fixed(120.0))
            )
            .align_items(Alignment::Center)
            .into()
    }

    /// Create browsing settings panel
    fn create_browsing_settings(&self) -> Element<Message> {
        let content = Column::new()
            .push(
                self.create_section_header("Browsing Settings", "Configure browsing behavior")
            )
            .push(Space::with_height(spacing::LG))
            .push(
                self.create_search_engine_selector()
            )
            .push(Space::with_height(spacing::XL))
            .push(
                self.create_homepage_selector()
            )
            .push(Space::with_height(spacing::XL))
            .push(
                self.create_toggle_setting("Restore Last Session", "Reopen tabs from previous session",
                    self.restore_last_session, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleRestoreSession(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Auto-fill Forms", "Automatically fill web forms",
                    self.auto_fill, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleAutoFill(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Password Manager", "Save and manage passwords",
                    self.password_manager, |enabled| Message::Settings(crate::app::SettingsMessage::TogglePasswordManager(enabled)))
            );

        container(content)
            .width(Length::Fill)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .padding(spacing::LG)
            .into()
    }

    /// Create search engine selector
    fn create_search_engine_selector(&self) -> Element<Message> {
        let engines = SearchEngine::ALL;
        let engine_names: Vec<&str> = engines.iter().map(|e| e.display_name()).collect();

        Row::new()
            .push(text("Search Engine:").size(typography::BODY).style(colors::TEXT_SECONDARY))
            .push(Space::with_width(spacing::MD))
            .push(
                pick_list(
                    engine_names,
                    Some(self.search_engine.display_name()),
                    |name| {
                        let engine = SearchEngine::ALL.iter()
                            .find(|e| e.display_name() == name)
                            .copied()
                            .unwrap_or(SearchEngine::DuckDuckGo);
                        Message::Settings(crate::app::SettingsMessage::SetSearchEngine(engine))
                    },
                )
                .padding(spacing::SM)
                .width(Length::Fixed(200.0))
            )
            .align_items(Alignment::Center)
            .into()
    }

    /// Create homepage selector
    fn create_homepage_selector(&self) -> Element<Message> {
        let homepage_types = HomepageType::ALL;
        let type_names: Vec<&str> = homepage_types.iter().map(|t| t.display_name()).collect();

        let content = Column::new()
            .push(
                Row::new()
                    .push(text("Homepage:").size(typography::BODY).style(colors::TEXT_SECONDARY))
                    .push(Space::with_width(spacing::MD))
                    .push(
                        pick_list(
                            type_names,
                            Some(self.homepage_type.display_name()),
                            |name| {
                                let homepage_type = HomepageType::ALL.iter()
                                    .find(|t| t.display_name() == name)
                                    .copied()
                                    .unwrap_or(HomepageType::NewTab);
                                Message::Settings(crate::app::SettingsMessage::SetHomepageType(homepage_type))
                            },
                        )
                        .padding(spacing::SM)
                        .width(Length::Fixed(200.0))
                    )
                    .align_items(Alignment::Center)
            );

        // Add custom homepage input if selected
        let content_with_input = if self.homepage_type == HomepageType::Custom {
            content.push(Space::with_height(spacing::MD))
                .push(
                    text_input("https://example.com", &self.custom_homepage)
                        .on_input(|url| Message::Settings(crate::app::SettingsMessage::SetCustomHomepage(url)))
                        .padding(spacing::SM)
                        .width(Length::Fill)
                )
        } else {
            content
        };

        container(content_with_input)
            .width(Length::Fill)
            .into()
    }

    /// Create advanced settings panel
    fn create_advanced_settings(&self) -> Element<Message> {
        let content = Column::new()
            .push(
                self.create_section_header("Advanced Settings", "Configure advanced browser options")
            )
            .push(Space::with_height(spacing::LG))
            .push(
                self.create_section_header("Development", "Developer options")
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Developer Mode", "Enable developer tools and features",
                    self.developer_mode, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleDeveloperMode(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Experimental Features", "Enable experimental browser features",
                    self.experimental_features, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleExperimentalFeatures(enabled)))
            )
            .push(Space::with_height(spacing::XL))
            .push(
                self.create_section_header("Performance", "Performance and system settings")
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Hardware Acceleration", "Use GPU for rendering",
                    self.hardware_acceleration, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleHardwareAcceleration(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Memory Saver", "Optimize memory usage",
                    self.memory_saver, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleMemorySaver(enabled)))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                self.create_toggle_setting("Background Sync", "Sync data in background",
                    self.background_sync, |enabled| Message::Settings(crate::app::SettingsMessage::ToggleBackgroundSync(enabled)))
            )
            .push(Space::with_height(spacing::XL))
            .push(
                self.create_log_level_selector()
            );

        container(content)
            .width(Length::Fill)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .padding(spacing::LG)
            .into()
    }

    /// Create log level selector
    fn create_log_level_selector(&self) -> Element<Message> {
        let log_levels = LogLevel::ALL;
        let level_names: Vec<&str> = log_levels.iter().map(|l| l.display_name()).collect();

        Row::new()
            .push(text("Log Level:").size(typography::BODY).style(colors::TEXT_SECONDARY))
            .push(Space::with_width(spacing::MD))
            .push(
                pick_list(
                    level_names,
                    Some(self.log_level.display_name()),
                    |name| {
                        let log_level = LogLevel::ALL.iter()
                            .find(|l| l.display_name() == name)
                            .copied()
                            .unwrap_or(LogLevel::Info);
                        Message::Settings(crate::app::SettingsMessage::SetLogLevel(log_level))
                    },
                )
                .padding(spacing::SM)
                .width(Length::Fixed(150.0))
            )
            .align_items(Alignment::Center)
            .into()
    }

    /// Create about section
    fn create_about_section(&self) -> Element<Message> {
        let content = Column::new()
            .push(
                self.create_section_header("About Citadel Browser", "Privacy-focused web browser")
            )
            .push(Space::with_height(spacing::LG))
            .push(
                Column::new()
                    .push(
                        Row::new()
                            .push(text("Version:").size(typography::BODY).style(colors::TEXT_SECONDARY))
                            .push(Space::with_width(spacing::MD))
                            .push(text("0.0.1-alpha").size(typography::BODY).style(colors::TEXT_PRIMARY))
                    )
                    .push(Space::with_height(spacing::MD))
                    .push(
                        Row::new()
                            .push(text("Build:").size(typography::BODY).style(colors::TEXT_SECONDARY))
                            .push(Space::with_width(spacing::MD))
                            .push(text("2025-12-06").size(typography::BODY).style(colors::TEXT_PRIMARY))
                    )
                    .push(Space::with_height(spacing::MD))
                    .push(
                        Row::new()
                            .push(text("Rust Version:").size(typography::BODY).style(colors::TEXT_SECONDARY))
                            .push(Space::with_width(spacing::MD))
                            .push(text("1.75.0").size(typography::BODY).style(colors::TEXT_PRIMARY))
                    )
                    .spacing(spacing::SM)
            )
            .push(Space::with_height(spacing::XL))
            .push(
                Column::new()
                    .push(text("🛡️ Privacy Features:").size(typography::H3).style(colors::TEXT_PRIMARY))
                    .push(Space::with_height(spacing::MD))
                    .push(text("• Zero-Knowledge Tab Isolation").size(typography::SMALL).style(colors::TEXT_SECONDARY))
                    .push(text("• Advanced Anti-Fingerprinting").size(typography::SMALL).style(colors::TEXT_SECONDARY))
                    .push(text("• Encrypted DNS Resolution").size(typography::SMALL).style(colors::TEXT_SECONDARY))
                    .push(text("• Tracker and Ad Blocking").size(typography::SMALL).style(colors::TEXT_SECONDARY))
                    .push(text("• Automatic Cookie Cleanup").size(typography::SMALL).style(colors::TEXT_SECONDARY))
                    .spacing(spacing::XS)
            )
            .push(Space::with_height(spacing::XL))
            .push(
                text("⚠️ This is alpha software - use at your own risk")
                    .size(typography::SMALL)
                    .style(colors::WARNING)
            )
            .push(Space::with_height(spacing::MD))
            .push(
                text("Built with ❤️ and Rust for privacy-conscious users")
                    .size(typography::SMALL)
                    .style(colors::TEXT_MUTED)
            );

        container(content)
            .width(Length::Fill)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .padding(spacing::LG)
            .into()
    }

    /// Helper: Create section header
    fn create_section_header(&self, title: &str, description: &str) -> Element<Message> {
        Column::new()
            .push(text(title).size(typography::H2).style(colors::TEXT_PRIMARY))
            .push(Space::with_height(spacing::XS))
            .push(text(description).size(typography::SMALL).style(colors::TEXT_MUTED))
            .into()
    }

    /// Helper: Create toggle setting
    fn create_toggle_setting<F>(&self, title: &str, description: &str, enabled: bool, on_toggle: F) -> Element<Message>
    where
        F: Fn(bool) -> Message + 'static,
    {
        Row::new()
            .push(
                Column::new()
                    .push(text(title).size(typography::BODY).style(colors::TEXT_PRIMARY))
                    .push(text(description).size(typography::CAPTION).style(colors::TEXT_MUTED))
                    .spacing(spacing::XS)
            )
            .push(Space::with_width(Length::Fill))
            .push(
                toggler(None, enabled, on_toggle)
                    .size(spacing::LG)
            )
            .align_items(Alignment::Center)
            .into()
    }

    /// Helper: Create slider setting
    fn create_slider_setting<F>(&self, title: &str, description: &str, range: std::ops::RangeInclusive<u16>, value: u16, on_change: F) -> Element<Message>
    where
        F: Fn(u16) -> Message + 'static,
    {
        Column::new()
            .push(text(title).size(typography::BODY).style(colors::TEXT_PRIMARY))
            .push(text(description).size(typography::CAPTION).style(colors::TEXT_MUTED))
            .push(Space::with_height(spacing::SM))
            .push(
                Row::new()
                    .push(
                        slider(range, value, on_change)
                            .width(Length::Fill)
                            .step(1u16)
                    )
                    .push(Space::with_width(spacing::MD))
                    .push(text(format!("{}", value)).size(typography::SMALL).style(colors::TEXT_SECONDARY))
                    .align_items(Alignment::Center)
            )
            .spacing(spacing::XS)
            .into()
    }
}

impl Default for SettingsPanel {
    fn default() -> Self {
        Self::new()
    }
}