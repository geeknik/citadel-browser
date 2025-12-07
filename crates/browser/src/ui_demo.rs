//! UI Demo and Integration Examples
//!
//! This module demonstrates how to integrate and use Citadel Browser's
//! modern UI components with practical examples and best practices.

use std::sync::Arc;
use iced::{Element, Command, Length, Alignment, Theme};
use citadel_tabs::{SendSafeTabManager as TabManager};
use citadel_networking::{NetworkConfig, PrivacyLevel, DnsProvider};

use crate::app::{Message, ViewportInfo, ScrollState, ZoomLevel};
use crate::renderer::CitadelRenderer;
use crate::ui_modern::{CitadelModernUI, ModernUIMessage};
use crate::theme::{CitadelTheme, ThemeManager};
use crate::settings_panel::{SettingsPanel, SettingsMessage, SettingsCategory};

/// Demo application showing UI integration
pub struct CitadelUIDemo {
    /// Modern UI implementation
    modern_ui: CitadelModernUI,
    /// Theme manager
    theme_manager: ThemeManager,
    /// Settings panel
    settings_panel: SettingsPanel,
    /// Network configuration
    network_config: NetworkConfig,
    /// Demo mode state
    demo_mode: DemoMode,
    /// Performance metrics for demo
    demo_metrics: DemoMetrics,
}

/// Demo display modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoMode {
    /// Show all UI features
    Complete,
    /// Focus on privacy features
    PrivacyFocused,
    /// Minimal UI demo
    Minimal,
    /// Accessibility demo
    Accessibility,
    /// Performance showcase
    Performance,
}

/// Demo performance metrics
#[derive(Debug, Clone)]
pub struct DemoMetrics {
    pub trackers_blocked: usize,
    pub fingerprints_prevented: usize,
    pub data_saved_mb: f64,
    pub tabs_isolated: usize,
    pub secure_connections: usize,
    pub scan_time_ms: u64,
}

/// Demo-specific messages
#[derive(Debug, Clone)]
pub enum DemoMessage {
    /// Switch demo mode
    SetDemoMode(DemoMode),
    /// Simulate privacy event
    SimulateTrackerBlocked,
    SimulateFingerprintBlocked,
    SimulateSecureConnection,
    /// Update demo metrics
    UpdateMetrics,
    /// Showcase theme switching
    CycleThemes,
    /// Performance demo
    TogglePerformanceOverlay,
    SimulateHighMemoryUsage,
    SimulateSlowNetwork,
    /// Accessibility demo
    ToggleHighContrast,
    IncreaseFontSize,
    DecreaseFontSize,
    /// Reset demo state
    ResetDemo,
}

impl CitadelUIDemo {
    /// Create a new demo instance
    pub fn new() -> Self {
        let mut network_config = NetworkConfig::default();
        network_config.privacy_level = PrivacyLevel::High;
        network_config.dns_provider = DnsProvider::Cloudflare;

        Self {
            modern_ui: CitadelModernUI::new(),
            theme_manager: ThemeManager::new(),
            settings_panel: SettingsPanel::new(),
            network_config,
            demo_mode: DemoMode::Complete,
            demo_metrics: DemoMetrics {
                trackers_blocked: 1247,
                fingerprints_prevented: 23,
                data_saved_mb: 15.7,
                tabs_isolated: 8,
                secure_connections: 42,
                scan_time_ms: 156,
            },
        }
    }

    /// Handle demo-specific updates
    pub fn update_demo(&mut self, message: DemoMessage) -> Command<Message> {
        match message {
            DemoMessage::SetDemoMode(mode) => {
                self.demo_mode = mode;
                self.apply_demo_mode_settings();
            }
            DemoMessage::SimulateTrackerBlocked => {
                self.demo_metrics.trackers_blocked += 1;
            }
            DemoMessage::SimulateFingerprintBlocked => {
                self.demo_metrics.fingerprints_prevented += 1;
            }
            DemoMessage::SimulateSecureConnection => {
                self.demo_metrics.secure_connections += 1;
            }
            DemoMessage::UpdateMetrics => {
                // Simulate real-time metric updates
                self.demo_metrics.data_saved_mb += 0.1;
                self.demo_metrics.scan_time_ms = rand::random::<u64>() % 300;
            }
            DemoMessage::CycleThemes => {
                self.theme_manager.toggle_theme();
            }
            DemoMessage::TogglePerformanceOverlay => {
                // Show/hide performance metrics overlay
            }
            DemoMessage::SimulateHighMemoryUsage => {
                // Demo memory pressure scenarios
            }
            DemoMessage::SimulateSlowNetwork => {
                // Demo slow connection handling
            }
            DemoMessage::ToggleHighContrast => {
                let theme = match self.theme_manager.current_theme() {
                    CitadelTheme::Dark => CitadelTheme::HighContrast,
                    CitadelTheme::HighContrast => CitadelTheme::Dark,
                    other => other,
                };
                self.theme_manager.set_theme(theme);
            }
            DemoMessage::IncreaseFontSize => {
                // Increase global font size for accessibility
            }
            DemoMessage::DecreaseFontSize => {
                // Decrease global font size
            }
            DemoMessage::ResetDemo => {
                *self = Self::new();
            }
        }
        Command::none()
    }

    /// Apply settings based on demo mode
    fn apply_demo_mode_settings(&mut self) {
        match self.demo_mode {
            DemoMode::Complete => {
                self.theme_manager.set_theme(CitadelTheme::Dark);
                self.network_config.privacy_level = PrivacyLevel::High;
            }
            DemoMode::PrivacyFocused => {
                self.theme_manager.set_theme(CitadelTheme::Dark);
                self.network_config.privacy_level = PrivacyLevel::Maximum;
                self.settings_panel.update(SettingsMessage::SetPrivacyLevel(PrivacyLevel::Maximum));
            }
            DemoMode::Minimal => {
                self.theme_manager.set_theme(CitadelTheme::Light);
                self.network_config.privacy_level = PrivacyLevel::Balanced;
            }
            DemoMode::Accessibility => {
                self.theme_manager.set_theme(CitadelTheme::HighContrast);
                self.settings_panel.update(SettingsMessage::SetFontSize(20));
                self.settings_panel.update(SettingsMessage::ToggleCompactMode(false));
            }
            DemoMode::Performance => {
                self.theme_manager.set_theme(CitadelTheme::Dark);
                self.settings_panel.update(SettingsMessage::ToggleAnimations(false));
                self.settings_panel.update(SettingsMessage::ToggleMemorySaver(true));
            }
        }
    }

    /// Create demo showcase view
    pub fn view_demo<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        match self.demo_mode {
            DemoMode::Complete => self.create_complete_demo(tab_manager, renderer, viewport_info, scroll_state),
            DemoMode::PrivacyFocused => self.create_privacy_demo(tab_manager, renderer, viewport_info, scroll_state),
            DemoMode::Minimal => self.create_minimal_demo(tab_manager, renderer, viewport_info, scroll_state),
            DemoMode::Accessibility => self.create_accessibility_demo(tab_manager, renderer, viewport_info, scroll_state),
            DemoMode::Performance => self.create_performance_demo(tab_manager, renderer, viewport_info, scroll_state),
        }
    }

    /// Create complete demo with all features
    fn create_complete_demo<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        use iced::widget::{container, Column, Row, Space, text, button};
        use crate::ui_modern::{colors, typography, spacing, GlassStyle};

        // Main content with modern UI
        let main_content = self.modern_ui.view(tab_manager, &self.network_config, renderer, viewport_info, scroll_state);

        // Demo controls overlay
        let demo_controls = container(
            Column::new()
                .push(
                    Row::new()
                        .push(text("🎨 UI Demo Mode").size(typography::H3).style(colors::TEXT_PRIMARY))
                        .push(Space::with_width(Length::Fill))
                        .push(
                            button(text("×").size(20))
                                .padding(spacing::SM)
                                .style(iced::theme::Button::Text)
                                .on_press(Message::Demo(DemoMessage::ResetDemo))
                        )
                        .align_items(Alignment::Center)
                )
                .push(Space::with_height(spacing::MD))
                .push(self.create_demo_mode_selector())
                .push(Space::with_height(spacing::LG))
                .push(self.create_privacy_demo_panel())
                .push(Space::with_height(spacing::LG))
                .push(self.create_theme_demo_panel())
                .spacing(spacing::SM)
                .align_items(iced::Alignment::Center)
        )
        .width(Length::Fill)
        .padding(spacing::LG)
        .style(iced::theme::Container::Custom(Box::new(GlassStyle)));

        // Demo overlay in corner
        let demo_overlay = container(
            Column::new()
                .push(text("Citadel Browser UI Demo").size(typography::SMALL).style(colors::TEXT_MUTED))
                .push(Space::with_height(spacing::XS))
                .push(text(format!("Mode: {:?}", self.demo_mode)).size(typography::TINY).style(colors::TEXT_MUTED))
                .push(Space::with_height(spacing::XS))
                .push(text(format!("Theme: {:?}", self.theme_manager.current_theme())).size(typography::TINY).style(colors::TEXT_MUTED))
        )
        .padding(spacing::SM)
        .style(iced::theme::Container::Custom(Box::new(GlassStyle)));

        // Combine main content with demo overlay
        iced::widget::layer_stack(main_content, demo_overlay).into()
    }

    /// Create privacy-focused demo
    fn create_privacy_demo<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        // Emphasize privacy features
        let mut enhanced_config = self.network_config.clone();
        enhanced_config.privacy_level = PrivacyLevel::Maximum;

        self.modern_ui.view(tab_manager, &enhanced_config, renderer, viewport_info, scroll_state)
    }

    /// Create minimal UI demo
    fn create_minimal_demo<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        use crate::ui_modern::{colors, spacing};

        // Ultra-minimal interface
        let minimal_content = iced::widget::column!(
            iced::widget::text("Minimal browsing experience")
                .size(24)
                .style(colors::TEXT_PRIMARY),
            iced::widget::text("Maximum focus, minimum distraction")
                .size(14)
                .style(colors::TEXT_MUTED),
            iced::widget::container(
                renderer.render()
            )
            .width(iced::Length::Fill)
            .height(iced::Length::Fill)
            .padding(spacing::MD)
        )
        .spacing(spacing::LG)
        .align_items(iced::Alignment::Center);

        iced::widget::container(minimal_content)
            .width(iced::Length::Fill)
            .height(iced::Length::Fill)
            .center_x()
            .center_y()
            .into()
    }

    /// Create accessibility demo
    fn create_accessibility_demo<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        // High contrast and large text
        let mut accessible_config = self.network_config.clone();
        accessible_config.privacy_level = PrivacyLevel::High;

        self.modern_ui.view(tab_manager, &accessible_config, renderer, viewport_info, scroll_state)
    }

    /// Create performance demo
    fn create_performance_demo<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        use iced::widget::{container, Column, Row, Space, text, progress_bar};
        use crate::ui_modern::{colors, typography, spacing};

        // Show performance metrics
        let performance_panel = container(
            Column::new()
                .push(text("Performance Dashboard").size(typography::H2).style(colors::TEXT_PRIMARY))
                .push(Space::with_height(spacing::MD))
                .push(
                    Row::new()
                        .push(text("Memory Usage").size(typography::BODY).style(colors::TEXT_SECONDARY))
                        .push(Space::with_width(Length::Fill))
                        .push(text("245 MB").size(typography::BODY).style(colors::INFO))
                )
                .push(
                    progress_bar(0.0..=512.0, 245.0)
                        .width(Length::Fill)
                )
                .push(Space::with_height(spacing::MD))
                .push(
                    Row::new()
                        .push(text("CPU Usage").size(typography::BODY).style(colors::TEXT_SECONDARY))
                        .push(Space::with_width(Length::Fill))
                        .push(text("12%").size(typography::BODY).style(colors::SUCCESS))
                )
                .push(
                    progress_bar(0.0..=100.0, 12.0)
                        .width(Length::Fill)
                )
                .push(Space::with_height(spacing::MD))
                .push(
                    Row::new()
                        .push(text("Network Latency").size(typography::BODY).style(colors::TEXT_SECONDARY))
                        .push(Space::with_width(Length::Fill))
                        .push(text("42 ms").size(typography::BODY).style(colors::SUCCESS))
                )
                .spacing(spacing::SM)
        )
        .width(Length::Fill)
        .padding(spacing::LG)
        .style(iced::theme::Container::Custom(Box::new(crate::ui_modern::GlassStyle)));

        // Combine with main content
        let main_content = self.modern_ui.view(tab_manager, &self.network_config, renderer, viewport_info, scroll_state);

        iced::widget::layer_stack(main_content, performance_panel).into()
    }

    /// Create demo mode selector
    fn create_demo_mode_selector(&self) -> Element<Message> {
        use iced::widget::{Row, button, text};
        use crate::ui_modern::{spacing, typography};

        let modes = [
            (DemoMode::Complete, "Complete"),
            (DemoMode::PrivacyFocused, "Privacy"),
            (DemoMode::Minimal, "Minimal"),
            (DemoMode::Accessibility, "A11y"),
            (DemoMode::Performance, "Perf"),
        ];

        let mut row = Row::new().spacing(spacing::SM);

        for (mode, label) in modes {
            let is_active = self.demo_mode == mode;
            row = row.push(
                button(
                    text(label).size(typography::SMALL)
                )
                .padding([spacing::SM, spacing::MD])
                .style(if is_active { iced::theme::Button::Primary } else { iced::theme::Button::Secondary })
                .on_press(Message::Demo(DemoMessage::SetDemoMode(mode)))
            );
        }

        container(row)
            .center_x()
            .into()
    }

    /// Create privacy demo panel
    fn create_privacy_demo_panel(&self) -> Element<Message> {
        use iced::widget::{Column, Row, button, text, Space};
        use crate::ui_modern::{colors, typography, spacing};

        container(
            Column::new()
                .push(text("Privacy Protection Demo").size(typography::H3).style(colors::TEXT_PRIMARY))
                .push(Space::with_height(spacing::MD))
                .push(
                    Row::new()
                        .push(text(format!("🛡️ Trackers Blocked: {}", self.demo_metrics.trackers_blocked))
                            .size(typography::SMALL)
                            .style(colors::PRIVACY_MAX))
                        .push(Space::with_width(spacing::MD))
                        .push(
                            button(text("Block More"))
                                .padding(spacing::SM)
                                .style(iced::theme::Button::Primary)
                                .on_press(Message::Demo(DemoMessage::SimulateTrackerBlocked))
                        )
                        .align_items(iced::Alignment::Center)
                )
                .push(Space::with_height(spacing::SM))
                .push(
                    Row::new()
                        .push(text(format!("🔒 Fingerprints Prevented: {}", self.demo_metrics.fingerprints_prevented))
                            .size(typography::SMALL)
                            .style(colors::PRIVACY_HIGH))
                        .push(Space::with_width(spacing::MD))
                        .push(
                            button(text("Prevent"))
                                .padding(spacing::SM)
                                .style(iced::theme::Button::Secondary)
                                .on_press(Message::Demo(DemoMessage::SimulateFingerprintBlocked))
                        )
                        .align_items(iced::Alignment::Center)
                )
                .spacing(spacing::SM)
        )
        .width(Length::Fill)
        .padding(spacing::MD)
        .style(iced::theme::Container::Custom(Box::new(crate::ui_modern::CardStyle)))
        .into()
    }

    /// Create theme demo panel
    fn create_theme_demo_panel(&self) -> Element<Message> {
        use iced::widget::{Row, button, text};
        use crate::ui_modern::{spacing, typography};

        Row::new()
            .push(text("Theme:").size(typography::BODY).style(crate::ui_modern::colors::TEXT_SECONDARY))
            .push(Space::with_width(spacing::MD))
            .push(
                button(text("Cycle Theme"))
                    .padding(spacing::SM)
                    .style(iced::theme::Button::Secondary)
                    .on_press(Message::Demo(DemoMessage::CycleThemes))
            )
            .push(Space::with_width(spacing::MD))
            .push(
                button(text("High Contrast"))
                    .padding(spacing::SM)
                    .style(iced::theme::Button::Text)
                    .on_press(Message::Demo(DemoMessage::ToggleHighContrast))
            )
            .align_items(iced::Alignment::Center)
            .into()
    }

    /// Get current demo metrics
    pub fn get_demo_metrics(&self) -> &DemoMetrics {
        &self.demo_metrics
    }

    /// Get current demo mode
    pub fn get_demo_mode(&self) -> DemoMode {
        self.demo_mode
    }

    /// Check if settings panel should be visible
    pub fn should_show_settings(&self) -> bool {
        self.settings_panel.is_visible()
    }

    /// Get settings panel view
    pub fn get_settings_view(&self) -> Element<Message> {
        self.settings_panel.view()
    }
}

impl Default for CitadelUIDemo {
    fn default() -> Self {
        Self::new()
    }
}