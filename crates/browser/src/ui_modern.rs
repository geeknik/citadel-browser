//! Modern UI implementation for Citadel Browser
//!
//! This module implements a cutting-edge, privacy-focused user interface
//! following 2025 design trends: radical minimalism, prominent privacy indicators,
//! and intelligent adaptive interfaces.

use std::sync::Arc;
use iced::{
    widget::{button, container, text, text_input, scrollable, Space, Column, Row,
             checkbox, slider, tooltip, progress_bar, horizontal_rule, vertical_rule},
    Element, Length, Color, Alignment, theme, Background,
    Font, Padding
};
use citadel_tabs::{SendSafeTabManager as TabManager};
use crate::app::{Message, ViewportInfo, ScrollState, ZoomLevel, LoadingState};
use crate::renderer::CitadelRenderer;
use citadel_networking::{NetworkConfig, PrivacyLevel};

// ====== MODERN DESIGN TOKENS ======

/// Citadel Browser Modern Color System
pub mod colors {
    use iced::Color;

    // Primary brand colors - privacy focused
    pub const PRIMARY: Color = Color::from_rgb(0.05, 0.45, 0.90);      // Deep trust blue
    pub const PRIMARY_LIGHT: Color = Color::from_rgb(0.15, 0.55, 1.0);  // Bright trust blue
    pub const PRIMARY_DARK: Color = Color::from_rgb(0.0, 0.35, 0.80);   // Deep trust blue dark

    // Privacy/security colors
    pub const PRIVACY_MAX: Color = Color::from_rgb(0.0, 0.75, 0.25);    // Shield green
    pub const PRIVACY_HIGH: Color = Color::from_rgb(0.0, 0.60, 0.80);   // Protection cyan
    pub const PRIVACY_BALANCED: Color = Color::from_rgb(0.90, 0.60, 0.0); // Balanced amber
    pub const PRIVACY_CUSTOM: Color = Color::from_rgb(0.50, 0.50, 0.50); // Custom gray

    // Semantic colors
    pub const SUCCESS: Color = Color::from_rgb(0.0, 0.75, 0.25);
    pub const WARNING: Color = Color::from_rgb(0.90, 0.60, 0.0);
    pub const ERROR: Color = Color::from_rgb(0.90, 0.25, 0.25);
    pub const INFO: Color = Color::from_rgb(0.0, 0.60, 0.80);

    // Neutral palette - dark theme focused
    pub const BACKGROUND_DARK: Color = Color::from_rgb(0.08, 0.08, 0.12);   // Deep space
    pub const BACKGROUND_CARD: Color = Color::from_rgb(0.12, 0.12, 0.18);  // Elevated surface
    pub const BACKGROUND_HOVER: Color = Color::from_rgb(0.15, 0.15, 0.22); // Interactive surface
    pub const BACKGROUND_ACTIVE: Color = Color::from_rgb(0.18, 0.18, 0.26); // Pressed surface

    pub const BORDER_SUBTLE: Color = Color::from_rgb(0.20, 0.20, 0.30);   // Subtle borders
    pub const BORDER_FOCUS: Color = Color::from_rgb(0.25, 0.55, 0.90);    // Focus ring

    pub const TEXT_PRIMARY: Color = Color::from_rgb(0.95, 0.95, 0.98);    // High contrast
    pub const TEXT_SECONDARY: Color = Color::from_rgb(0.70, 0.70, 0.75);  // Muted text
    pub const TEXT_MUTED: Color = Color::from_rgb(0.45, 0.45, 0.50);      // Helper text

    // Glass morphism overlay
    pub const GLASS_OVERLAY: Color = Color::from_rgba(0.12, 0.12, 0.18, 0.70);
    pub const GLASS_BORDER: Color = Color::from_rgba(1.0, 1.0, 1.0, 0.10);
}

/// Typography scale for modern browser UI
pub mod typography {
    use iced::Font;

    pub const DISPLAY: f32 = 36.0;
    pub const H1: f32 = 30.0;
    pub const H2: f32 = 24.0;
    pub const H3: f32 = 20.0;
    pub const BODY: f32 = 16.0;
    pub const SMALL: f32 = 14.0;
    pub const CAPTION: f32 = 12.0;
    pub const TINY: f32 = 10.0;

    // System font stack for best performance
    pub const SYSTEM: Font = Font::DEFAULT;

    // Monospace for code/technical content
    pub const MONOSPACE: Font = Font {
        family: iced::font::Family::Monospace,
        weight: iced::font::Weight::Normal,
        stretch: iced::font::Stretch::Normal,
        style: iced::font::Style::Normal,
    };
}

/// Spacing system based on 8px grid
pub mod spacing {
    pub const XS: u16 = 4;   // 0.25rem
    pub const SM: u16 = 8;   // 0.5rem
    pub const MD: u16 = 16;  // 1rem
    pub const LG: u16 = 24;  // 1.5rem
    pub const XL: u16 = 32;  // 2rem
    pub const XXL: u16 = 48; // 3rem
}

/// Border radius for modern aesthetics
pub mod radius {
    pub const NONE: f32 = 0.0;
    pub const SM: f32 = 4.0;
    pub const MD: f32 = 8.0;
    pub const LG: f32 = 12.0;
    pub const XL: f32 = 16.0;
    pub const PILL: f32 = 999.0; // For pills and badges
}

// ====== CUSTOM STYLESHEETS ======

/// Modern glass morphism style for floating panels
#[derive(Clone, Copy, Debug)]
pub struct GlassStyle;

impl container::StyleSheet for GlassStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(colors::GLASS_OVERLAY)),
            border: iced::Border {
                color: colors::GLASS_BORDER,
                width: 1.0,
                radius: radius::XL.into(),
            },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.30),
                offset: iced::Vector::new(0.0, 8.0),
                blur_radius: 24.0,
            },
            text_color: Some(colors::TEXT_PRIMARY),
        }
    }
}

/// Modern toolbar style with subtle elevation
#[derive(Clone, Copy, Debug)]
pub struct ToolbarStyle;

impl container::StyleSheet for ToolbarStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(colors::BACKGROUND_CARD)),
            border: iced::Border {
                color: colors::BORDER_SUBTLE,
                width: 0.0,
                radius: 0.0.into(),
            },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.10),
                offset: iced::Vector::new(0.0, 1.0),
                blur_radius: 0.0,
            },
            text_color: Some(colors::TEXT_PRIMARY),
        }
    }
}

/// Modern card style with subtle depth
#[derive(Clone, Copy, Debug)]
pub struct CardStyle;

impl container::StyleSheet for CardStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        container::Appearance {
            background: Some(Background::Color(colors::BACKGROUND_CARD)),
            border: iced::Border {
                color: colors::BORDER_SUBTLE,
                width: 1.0,
                radius: radius::MD.into(),
            },
            shadow: iced::Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.15),
                offset: iced::Vector::new(0.0, 4.0),
                blur_radius: 8.0,
            },
            text_color: Some(colors::TEXT_PRIMARY),
        }
    }
}

/// Privacy indicator style with accent colors
#[derive(Clone, Copy, Debug)]
pub struct PrivacyIndicatorStyle {
    pub privacy_level: PrivacyLevel,
}

impl container::StyleSheet for PrivacyIndicatorStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> container::Appearance {
        let accent_color = match self.privacy_level {
            PrivacyLevel::Maximum => colors::PRIVACY_MAX,
            PrivacyLevel::High => colors::PRIVACY_HIGH,
            PrivacyLevel::Balanced => colors::PRIVACY_BALANCED,
            PrivacyLevel::Custom => colors::PRIVACY_CUSTOM,
        };

        container::Appearance {
            background: Some(Background::Color(accent_color)),
            border: iced::Border {
                color: accent_color,
                width: 1.0,
                radius: radius::PILL.into(),
            },
            shadow: iced::Shadow {
                color: Color::from_rgba(accent_color.r, accent_color.g, accent_color.b, 0.25),
                offset: iced::Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
            text_color: Some(colors::TEXT_PRIMARY),
        }
    }
}

impl button::StyleSheet for PrivacyIndicatorStyle {
    type Style = iced::Theme;

    fn active(&self, _style: &Self::Style) -> button::Appearance {
        let accent_color = match self.privacy_level {
            PrivacyLevel::Maximum => colors::PRIVACY_MAX,
            PrivacyLevel::High => colors::PRIVACY_HIGH,
            PrivacyLevel::Balanced => colors::PRIVACY_BALANCED,
            PrivacyLevel::Custom => colors::PRIVACY_CUSTOM,
        };

        button::Appearance {
            background: Some(Background::Color(accent_color)),
            border: iced::Border {
                color: accent_color,
                width: 1.0,
                radius: radius::PILL.into(),
            },
            shadow: iced::Shadow {
                color: Color::from_rgba(accent_color.r, accent_color.g, accent_color.b, 0.25),
                offset: iced::Vector::new(0.0, 2.0),
                blur_radius: 4.0,
            },
            shadow_offset: iced::Vector::new(0.0, 0.0),
            text_color: colors::TEXT_PRIMARY,
        }
    }

    fn hovered(&self, style: &Self::Style) -> button::Appearance {
        let active = self.active(style);
        button::Appearance {
            shadow: iced::Shadow {
                offset: iced::Vector::new(0.0, 4.0),
                blur_radius: 8.0,
                ..active.shadow
            },
            ..active
        }
    }

    fn pressed(&self, style: &Self::Style) -> button::Appearance {
        let active = self.active(style);
        button::Appearance {
            shadow: iced::Shadow {
                offset: iced::Vector::new(0.0, 1.0),
                blur_radius: 2.0,
                ..active.shadow
            },
            ..active
        }
    }

    fn disabled(&self, style: &Self::Style) -> button::Appearance {
        let active = self.active(style);
        button::Appearance {
            background: active.background.map(|b| match b {
                Background::Color(c) => Background::Color(Color { a: c.a * 0.5, ..c }),
                Background::Gradient(g) => Background::Gradient(g),
            }),
            text_color: Color { a: active.text_color.a * 0.5, ..active.text_color },
            ..active
        }
    }
}

/// Modern tab style with privacy indicators
#[derive(Clone, Debug)]
pub struct TabStyle {
    pub is_active: bool,
    pub has_privacy_enhanced: bool,
    pub is_loading: bool,
}

impl button::StyleSheet for TabStyle {
    type Style = iced::Theme;

    fn active(&self, _style: &Self::Style) -> button::Appearance {
        let (background, border_color, text_color) = if self.is_active {
            (colors::BACKGROUND_ACTIVE, colors::PRIMARY, colors::TEXT_PRIMARY)
        } else {
            (colors::BACKGROUND_CARD, colors::BORDER_SUBTLE, colors::TEXT_SECONDARY)
        };

        let mut appearance = button::Appearance {
            background: Some(Background::Color(background)),
            border: iced::Border {
                color: border_color,
                width: if self.is_active { 2.0 } else { 1.0 },
                radius: radius::MD.into(),
            },
            text_color: text_color,
            shadow: iced::Shadow::default(),
            shadow_offset: iced::Vector::new(0.0, 0.0),
        };

        // Add privacy indicator glow
        if self.has_privacy_enhanced {
            appearance.shadow = iced::Shadow {
                color: Color::from_rgba(0.0, 0.75, 0.25, 0.20),
                offset: iced::Vector::new(0.0, 0.0),
                blur_radius: 8.0,
            };
        }

        // Add loading animation hint
        if self.is_loading {
            appearance.border.color = colors::INFO;
        }

        appearance
    }

    fn hovered(&self, style: &Self::Style) -> button::Appearance {
        let mut active = self.active(style);
        if !self.is_active {
             active.background = Some(Background::Color(colors::BACKGROUND_HOVER));
        }
        active
    }

    fn pressed(&self, style: &Self::Style) -> button::Appearance {
        let mut active = self.active(style);
        if !self.is_active {
             active.background = Some(Background::Color(colors::BACKGROUND_ACTIVE));
        }
        active
    }

    fn disabled(&self, style: &Self::Style) -> button::Appearance {
        let active = self.active(style);
        button::Appearance {
            background: active.background.map(|b| match b {
                Background::Color(c) => Background::Color(Color { a: c.a * 0.5, ..c }),
                Background::Gradient(g) => Background::Gradient(g),
            }),
            text_color: Color { a: active.text_color.a * 0.5, ..active.text_color },
            ..active
        }
    }
}

// ====== MAIN UI COMPONENT ======

/// Modern Citadel Browser UI with 2025 design principles
#[derive(Debug, Clone)]
pub struct CitadelModernUI {
    /// Address bar state
    address_bar_value: String,
    address_bar_focused: bool,
    address_bar_secure: bool,

    /// UI state
    sidebar_collapsed: bool,
    show_privacy_dashboard: bool,
    show_settings_panel: bool,

    /// Animation states
    privacy_pulse_phase: f32,
    loading_animation_offset: f32,

    /// Quick actions visibility
    quick_actions_visible: bool,
}

/// Enhanced UI messages for modern interactions
#[derive(Debug, Clone)]
pub enum ModernUIMessage {
    /// Address bar interactions
    AddressBarChanged(String),
    AddressBarSubmitted,
    AddressBarFocused,
    AddressBarUnfocused,

    /// Privacy controls
    TogglePrivacyLevel,
    OpenPrivacyDashboard,
    ClosePrivacyDashboard,

    /// Layout controls
    ToggleSidebar,
    ToggleSettings,

    /// Quick actions
    ShowQuickActions,
    HideQuickActions,

    /// Animations
    UpdatePrivacyPulse,
    UpdateLoadingAnimation,

    /// Tab interactions
    CloseTabWithAnimation(uuid::Uuid),
    SwitchTabWithAnimation(uuid::Uuid),

    /// Search and navigation
    QuickSearch(String),
    NavigateToSuggestion(String),
}

impl CitadelModernUI {
    /// Create a new modern UI state
    pub fn new() -> Self {
        Self {
            address_bar_value: String::new(),
            address_bar_focused: false,
            address_bar_secure: false,
            sidebar_collapsed: false,
            show_privacy_dashboard: false,
            show_settings_panel: false,
            privacy_pulse_phase: 0.0,
            loading_animation_offset: 0.0,
            quick_actions_visible: false,
        }
    }

    /// Update UI state based on messages
    pub fn update(&mut self, message: ModernUIMessage) -> iced::Command<Message> {
        match message {
            ModernUIMessage::AddressBarChanged(value) => {
                self.address_bar_value = value;
            }
            ModernUIMessage::AddressBarSubmitted => {
                if !self.address_bar_value.trim().is_empty() {
                    let url = self.address_bar_value.clone();
                    return iced::Command::perform(
                        async move {},
                        move |_| Message::Navigate(url),
                    );
                }
            }
            ModernUIMessage::AddressBarFocused => {
                self.address_bar_focused = true;
                self.quick_actions_visible = true;
            }
            ModernUIMessage::AddressBarUnfocused => {
                self.address_bar_focused = false;
                // Hide quick actions after a delay
            }
            ModernUIMessage::ToggleSidebar => {
                self.sidebar_collapsed = !self.sidebar_collapsed;
            }
            ModernUIMessage::TogglePrivacyLevel => {
                // Cycle through privacy levels
            }
            ModernUIMessage::OpenPrivacyDashboard => {
                self.show_privacy_dashboard = true;
            }
            ModernUIMessage::ClosePrivacyDashboard => {
                self.show_privacy_dashboard = false;
            }
            ModernUIMessage::UpdatePrivacyPulse => {
                self.privacy_pulse_phase = (self.privacy_pulse_phase + 0.1) % 1.0;
            }
            ModernUIMessage::UpdateLoadingAnimation => {
                self.loading_animation_offset = (self.loading_animation_offset + 1.0) % 3.0;
            }
            _ => {}
        }
        iced::Command::none()
    }

    /// Create the main modern UI view
    pub fn view<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        network_config: &NetworkConfig,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        let main_content = Column::new()
            .push(self.create_floating_toolbar(tab_manager, network_config, viewport_info))
            .push(self.create_modern_tabs_bar(tab_manager))
            .push(self.create_content_area(tab_manager, renderer, viewport_info, scroll_state))
            .spacing(0);

        // Add privacy dashboard overlay if visible
        if self.show_privacy_dashboard {
            let content_with_dashboard = Column::new()
                .push(main_content)
                .push(self.create_privacy_dashboard(network_config));

            container(content_with_dashboard)
                .width(Length::Fill)
                .height(Length::Fill)
                .style(theme::Container::Custom(Box::new(GlassStyle)))
                .into()
        } else {
            container(main_content)
                .width(Length::Fill)
                .height(Length::Fill)
                .style(theme::Container::Custom(Box::new(ToolbarStyle)))
                .into()
        }
    }

    /// Create modern floating toolbar with minimal design
    fn create_floating_toolbar(
        &self,
        _tab_manager: &Arc<TabManager>,
        network_config: &NetworkConfig,
        viewport_info: &ViewportInfo,
    ) -> Element<Message> {
        // Navigation group - simplified
        let navigation = Row::new()
            .push(
                button(text("←").size(18))
                    .padding(spacing::SM)
                    .style(theme::Button::Text)
                    .on_press(Message::Back)
            )
            .push(
                button(text("→").size(18))
                    .padding(spacing::SM)
                    .style(theme::Button::Text)
                    .on_press(Message::Forward)
            )
            .push(
                button(text("⟳").size(18))
                    .padding(spacing::SM)
                    .style(theme::Button::Text)
                    .on_press(Message::Reload)
            )
            .spacing(spacing::XS);

        // Modern address bar with security indicators
        let address_bar = self.create_modern_address_bar();

        // Privacy indicator with pulse animation
        let privacy_indicator = self.create_animated_privacy_indicator(network_config);

        // Zoom controls - simplified
        let zoom = self.create_compact_zoom_controls(viewport_info);

        // Menu button
        let menu_button = button(text("⋮").size(20))
            .padding(spacing::SM)
            .style(theme::Button::Text)
            .on_press(Message::ToggleSettings);

        // Floating toolbar layout
        let toolbar = Row::new()
            .push(navigation)
            .push(Space::with_width(spacing::MD))
            .push(address_bar)
            .push(Space::with_width(spacing::MD))
            .push(zoom)
            .push(Space::with_width(spacing::SM))
            .push(privacy_indicator)
            .push(Space::with_width(spacing::SM))
            .push(menu_button)
            .align_items(Alignment::Center)
            .padding([spacing::MD, spacing::XL]);

        container(toolbar)
            .width(Length::Fill)
            .padding([spacing::SM, spacing::LG, 0, spacing::LG])
            .style(theme::Container::Custom(Box::new(GlassStyle)))
            .into()
    }

    /// Create modern address bar with security and autocomplete
    fn create_modern_address_bar(&self) -> Element<Message> {
        let address_input = text_input("Search or enter address...", &self.address_bar_value)
            .on_input(|value| Message::UI(crate::ui::UIMessage::AddressBarChanged(value)))
            .on_submit(Message::UI(crate::ui::UIMessage::AddressBarSubmitted))
            .padding([spacing::SM, spacing::MD])
            .width(Length::Fill)
            .style(theme::TextInput::Default);

        let address_with_security = Row::new()
            .push(if self.address_bar_secure {
                text("🔒").size(14).style(colors::PRIVACY_MAX)
            } else {
                text("🌐").size(14).style(colors::TEXT_MUTED)
            })
            .push(Space::with_width(spacing::SM))
            .push(address_input)
            .align_items(Alignment::Center);

        container(address_with_security)
            .width(Length::Fill)
            .padding(spacing::SM)
            .style(theme::Container::Custom(Box::new(GlassStyle)))
            .into()
    }

    /// Create animated privacy indicator
    fn create_animated_privacy_indicator(&self, network_config: &NetworkConfig) -> Element<Message> {
        let (privacy_text, privacy_color) = match network_config.privacy_level {
            PrivacyLevel::Maximum => ("MAX", colors::PRIVACY_MAX),
            PrivacyLevel::High => ("HIGH", colors::PRIVACY_HIGH),
            PrivacyLevel::Balanced => ("BAL", colors::PRIVACY_BALANCED),
            PrivacyLevel::Custom => ("CUST", colors::PRIVACY_CUSTOM),
        };

        let indicator_content = text(format!("🛡️ {}", privacy_text))
            .size(typography::SMALL)
            .style(privacy_color);

        button(indicator_content)
            .padding([spacing::XS, spacing::SM])
            .style(theme::Button::Custom(Box::new(PrivacyIndicatorStyle {
                privacy_level: network_config.privacy_level,
            })))
            .on_press(Message::UI(crate::ui::UIMessage::AddressBarFocused))
            .into()
    }

    /// Create compact zoom controls
    fn create_compact_zoom_controls(&self, viewport_info: &ViewportInfo) -> Element<Message> {
        let zoom_text = text(format!("{}%", viewport_info.zoom_level.as_percentage()))
            .size(typography::TINY)
            .style(colors::TEXT_SECONDARY);

        Row::new()
            .push(
                button(text("−").size(16))
                    .padding(spacing::XS)
                    .style(theme::Button::Text)
                    .on_press(Message::ZoomOut)
            )
            .push(Space::with_width(spacing::XS))
            .push(zoom_text)
            .push(Space::with_width(spacing::XS))
            .push(
                button(text("+").size(16))
                    .padding(spacing::XS)
                    .style(theme::Button::Text)
                    .on_press(Message::ZoomIn)
            )
            .align_items(Alignment::Center)
            .into()
    }

    /// Create modern tabs bar with privacy indicators
    fn create_modern_tabs_bar(&self, tab_manager: &Arc<TabManager>) -> Element<Message> {
        let tab_states = tab_manager.get_tab_states();

        let mut tab_row = Row::new().spacing(spacing::XS);

        // Add tabs with modern styling
        for tab_state in tab_states {
            let tab_title = if tab_state.title.is_empty() {
                "New Tab".to_string()
            } else {
                // Truncate long titles
                let mut title = tab_state.title.clone();
                if title.len() > 20 {
                    title.truncate(17);
                    title.push_str("...");
                }
                title
            };

            // Privacy indicator for tab
            let privacy_indicator = if matches!(tab_state.tab_type, citadel_tabs::TabType::Ephemeral) {
                Some(text("🛡️").size(10).style(colors::PRIVACY_MAX))
            } else {
                None
            };

            // Loading indicator
            let loading_indicator = if matches!(&tab_state.content, citadel_tabs::PageContent::Loading { .. }) {
                Some(text("⟳").size(10).style(colors::INFO))
            } else {
                None
            };

            let mut tab_content = Row::new()
                .align_items(Alignment::Center);

            if let Some(privacy) = privacy_indicator {
                tab_content = tab_content.push(privacy).push(Space::with_width(2));
            }

            tab_content = tab_content
                .push(text(tab_title).size(typography::SMALL))
                .push(Space::with_width(spacing::SM));

            if let Some(loading) = loading_indicator {
                tab_content = tab_content.push(loading);
            }

            // Close button
            tab_content = tab_content.push(
                button(text("×").size(14))
                    .padding(spacing::XS)
                    .style(theme::Button::Text)
                    .on_press(Message::CloseTab(tab_state.id))
            );

            let tab_button = button(container(tab_content).padding([spacing::SM, spacing::MD]))
                .padding(0)
                .style(theme::Button::Custom(Box::new(TabStyle {
                    is_active: tab_state.is_active,
                    has_privacy_enhanced: matches!(tab_state.tab_type, citadel_tabs::TabType::Ephemeral),
                    is_loading: matches!(&tab_state.content, citadel_tabs::PageContent::Loading { .. }),
                })))
                .on_press(Message::SwitchTab(tab_state.id));

            tab_row = tab_row.push(tab_button);
        }

        // New tab button
        let new_tab_button = button(
            text("+").size(18).style(colors::TEXT_SECONDARY)
        )
        .padding([spacing::SM, spacing::MD])
        .style(theme::Button::Custom(Box::new(TabStyle {
            is_active: false,
            has_privacy_enhanced: false,
            is_loading: false,
        })))
        .on_press(Message::NewTab {
            tab_type: citadel_tabs::TabType::Ephemeral,
            initial_url: None
        });

        tab_row = tab_row.push(new_tab_button);

        container(
            scrollable(tab_row)
                .direction(scrollable::Direction::Horizontal(
                    scrollable::Properties::default()
                ))
        )
        .width(Length::Fill)
        .padding([spacing::SM, spacing::LG])
        .style(theme::Container::Custom(Box::new(ToolbarStyle)))
        .into()
    }

    /// Create enhanced content area
    fn create_content_area<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        let tab_states = tab_manager.get_tab_states();

        if let Some(active_tab) = tab_states.iter().find(|tab| tab.is_active) {
            match &active_tab.content {
                citadel_tabs::PageContent::Loading { url } => {
                    self.create_modern_loading_view(url)
                }
                citadel_tabs::PageContent::Loaded { url, title, element_count, size_bytes, content: _ } => {
                    self.create_modern_content_view(url, title, *element_count, *size_bytes, renderer, viewport_info, scroll_state)
                }
                citadel_tabs::PageContent::Error { url, error } => {
                    self.create_modern_error_view(url, error)
                }
                citadel_tabs::PageContent::Empty => {
                    self.create_modern_empty_view()
                }
            }
        } else {
            self.create_modern_welcome_view()
        }
    }

    /// Create modern loading view with animated progress
    fn create_modern_loading_view(&self, url: &str) -> Element<Message> {
        let content = Column::new()
            .push(Space::with_height(Length::Fixed(100.0)))
            .push(
                container(
                    Column::new()
                        .push(text("🛡️ Citadel Browser").size(typography::H2).style(colors::TEXT_PRIMARY))
                        .push(Space::with_height(spacing::MD))
                        .push(text("Securing your connection...").size(typography::BODY).style(colors::TEXT_SECONDARY))
                        .push(Space::with_height(spacing::LG))
                        .push(
                            progress_bar(0.0..=1.0, (self.loading_animation_offset / 3.0))
                                .width(Length::Fixed(200.0))
                                .style(theme::ProgressBar::Primary)
                        )
                        .push(Space::with_height(spacing::MD))
                        .push(
                            Row::new()
                                .push(text("🔒").size(16))
                                .push(Space::with_width(spacing::SM))
                                .push(text("ZKVM Isolation Active").size(typography::SMALL).style(colors::PRIVACY_HIGH))
                                .align_items(Alignment::Center)
                        )
                        .push(Space::with_height(spacing::SM))
                        .push(text(format!("Loading: {}", url)).size(typography::CAPTION).style(colors::TEXT_MUTED))
                        .align_items(Alignment::Center)
                )
                .width(Length::Fill)
                .style(theme::Container::Custom(Box::new(GlassStyle)))
                .padding(spacing::XL)
            )
            .align_items(Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }

    /// Create modern error view with helpful suggestions
    fn create_modern_error_view(&self, url: &str, error: &str) -> Element<Message> {
        let content = Column::new()
            .push(Space::with_height(Length::Fixed(100.0)))
            .push(
                container(
                    Column::new()
                        .push(text("⚠️ Connection Error").size(typography::H2).style(colors::ERROR))
                        .push(Space::with_height(spacing::MD))
                        .push(text(format!("Could not load: {}", url)).size(typography::BODY).style(colors::TEXT_SECONDARY))
                        .push(Space::with_height(spacing::SM))
                        .push(text(error).size(typography::SMALL).style(colors::TEXT_MUTED))
                        .push(Space::with_height(spacing::LG))
                        .push(
                            button(text("Try Again").size(typography::BODY))
                                .padding([spacing::SM, spacing::LG])
                                .style(theme::Button::Primary)
                                .on_press(Message::Reload)
                        )
                        .push(Space::with_height(spacing::MD))
                        .push(
                            Row::new()
                                .push(text("🛡️").size(16))
                                .push(Space::with_width(spacing::SM))
                                .push(text("Protected by Citadel Security").size(typography::SMALL).style(colors::PRIVACY_HIGH))
                                .align_items(Alignment::Center)
                        )
                        .align_items(Alignment::Center)
                )
                .width(Length::Fill)
                .style(theme::Container::Custom(Box::new(GlassStyle)))
                .padding(spacing::XL)
            )
            .align_items(Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }

    /// Create modern empty tab view
    fn create_modern_empty_view(&self) -> Element<Message> {
        let content = Column::new()
            .push(Space::with_height(Length::Fixed(100.0)))
            .push(
                container(
                    Column::new()
                        .push(text("🛡️ New Private Tab").size(typography::H1).style(colors::TEXT_PRIMARY))
                        .push(Space::with_height(spacing::MD))
                        .push(text("Enhanced Privacy Protection Active").size(typography::BODY).style(colors::PRIVACY_HIGH))
                        .push(Space::with_height(spacing::LG))
                        .push(text("Enter a URL above to begin browsing").size(typography::SMALL).style(colors::TEXT_MUTED))
                        .push(Space::with_height(spacing::XL))
                        .push(
                            Column::new()
                                .push(text("🔒 ZKVM Tab Isolation").size(typography::SMALL).style(colors::TEXT_SECONDARY))
                                .push(Space::with_height(spacing::SM))
                                .push(text("🚫 Tracker Blocking").size(typography::SMALL).style(colors::TEXT_SECONDARY))
                                .push(Space::with_height(spacing::SM))
                                .push(text("🌐 Private DNS").size(typography::SMALL).style(colors::TEXT_SECONDARY))
                                .spacing(spacing::SM)
                        )
                        .align_items(Alignment::Center)
                )
                .width(Length::Fill)
                .style(theme::Container::Custom(Box::new(GlassStyle)))
                .padding(spacing::XL)
            )
            .align_items(Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }

    /// Create modern welcome view for new users
    fn create_modern_welcome_view(&self) -> Element<Message> {
        let content = Column::new()
            .push(Space::with_height(Length::Fixed(80.0)))
            .push(
                container(
                    Column::new()
                        .push(text("🛡️ Citadel Browser").size(typography::DISPLAY).style(colors::TEXT_PRIMARY))
                        .push(Space::with_height(spacing::MD))
                        .push(text("Privacy-First Web Browser").size(typography::H3).style(colors::TEXT_SECONDARY))
                        .push(Space::with_height(spacing::XL))
                        .push(
                            container(
                                text("⚠️ ALPHA SOFTWARE")
                                    .size(typography::BODY)
                                    .style(colors::WARNING)
                            )
                            .padding([spacing::SM, spacing::MD])
                            .style(theme::Container::Custom(Box::new(PrivacyIndicatorStyle {
                                privacy_level: PrivacyLevel::Custom,
                            })))
                        )
                        .push(Space::with_height(spacing::MD))
                        .push(text("Experimental - Use at your own risk").size(typography::SMALL).style(colors::TEXT_MUTED))
                        .push(Space::with_height(spacing::XXL))
                        .push(
                            Column::new()
                                .push(
                                    Row::new()
                                        .push(text("🔒").size(20))
                                        .push(Space::with_width(spacing::SM))
                                        .push(text("Zero-Knowledge Tab Isolation").size(typography::BODY).style(colors::TEXT_PRIMARY))
                                        .align_items(Alignment::Center)
                                )
                                .push(Space::with_height(spacing::MD))
                                .push(
                                    Row::new()
                                        .push(text("🛡️").size(20))
                                        .push(Space::with_width(spacing::SM))
                                        .push(text("Advanced Anti-Fingerprinting").size(typography::BODY).style(colors::TEXT_PRIMARY))
                                        .align_items(Alignment::Center)
                                )
                                .push(Space::with_height(spacing::MD))
                                .push(
                                    Row::new()
                                        .push(text("🌐").size(20))
                                        .push(Space::with_width(spacing::SM))
                                        .push(text("Private DNS & Encrypted Connections").size(typography::BODY).style(colors::TEXT_PRIMARY))
                                        .align_items(Alignment::Center)
                                )
                                .spacing(spacing::MD)
                        )
                        .push(Space::with_height(spacing::XL))
                        .push(text("Enter a URL in the address bar to begin").size(typography::SMALL).style(colors::TEXT_MUTED))
                        .align_items(Alignment::Center)
                )
                .width(Length::Fill)
                .style(theme::Container::Custom(Box::new(GlassStyle)))
                .padding(spacing::XL)
            )
            .align_items(Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }

    /// Create modern content view with enhanced header
    fn create_modern_content_view<'a>(
        &'a self,
        url: &str,
        title: &str,
        element_count: usize,
        size_bytes: usize,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        // Enhanced header with page info
        let header = self.create_modern_content_header(url, element_count, size_bytes, viewport_info, scroll_state);

        // Get rendered content
        let rendered_content = renderer.render();

        // Content with scrollable area
        let scrollable_content = scrollable(rendered_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .direction(scrollable::Direction::Both {
                vertical: scrollable::Properties::new(),
                horizontal: scrollable::Properties::new(),
            });

        let full_content = Column::new()
            .push(header)
            .push(scrollable_content)
            .spacing(0);

        container(full_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    /// Create modern content header with page information
    fn create_modern_content_header(
        &self,
        url: &str,
        element_count: usize,
        size_bytes: usize,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<Message> {
        // Format URL for display
        let display_url = if url.len() > 60 {
            format!("{}...", &url[..57])
        } else {
            url.to_string()
        };

        let header_content = Row::new()
            .push(
                Row::new()
                    .push(text("🔗").size(12).style(colors::INFO))
                    .push(Space::with_width(spacing::XS))
                    .push(text(display_url).size(typography::TINY).style(colors::TEXT_SECONDARY))
                    .align_items(Alignment::Center)
            )
            .push(text("•").size(typography::TINY).style(colors::TEXT_MUTED))
            .push(text(format!("{} elements", element_count)).size(typography::TINY).style(colors::TEXT_MUTED))
            .push(text("•").size(typography::TINY).style(colors::TEXT_MUTED))
            .push(text(format!("{} bytes", size_bytes)).size(typography::TINY).style(colors::TEXT_MUTED))
            .push(text("•").size(typography::TINY).style(colors::TEXT_MUTED))
            .push(text(format!("{}%", viewport_info.zoom_level.as_percentage())).size(typography::TINY).style(colors::INFO))
            .push(Space::with_width(spacing::MD))
            .push(
                Row::new()
                    .push(text("🛡️").size(12).style(colors::PRIVACY_HIGH))
                    .push(Space::with_width(spacing::XS))
                    .push(text("Secure").size(typography::TINY).style(colors::PRIVACY_HIGH))
                    .align_items(Alignment::Center)
            )
            .spacing(spacing::SM)
            .align_items(Alignment::Center);

        // Add scroll info if available
        let header_with_scroll = if let Some(scroll) = scroll_state {
            header_content
                .push(text("•").size(typography::TINY).style(colors::TEXT_MUTED))
                .push(text(format!("📍 ({:.0},{:.0})", scroll.x, scroll.y)).size(typography::TINY).style(colors::TEXT_MUTED))
        } else {
            header_content
        };

        container(header_with_scroll)
            .width(Length::Fill)
            .padding([spacing::SM, spacing::LG])
            .style(theme::Container::Custom(Box::new(ToolbarStyle)))
            .into()
    }

    /// Create privacy dashboard overlay
    fn create_privacy_dashboard(&self, network_config: &NetworkConfig) -> Element<Message> {
        let dashboard_content = Column::new()
            .push(
                Row::new()
                    .push(text("Privacy Dashboard").size(typography::H2).style(colors::TEXT_PRIMARY))
                    .push(Space::with_width(Length::Fill))
                    .push(
                        button(text("×").size(24))
                            .padding(spacing::SM)
                            .style(theme::Button::Text)
                            .on_press(Message::UI(crate::ui::UIMessage::AddressBarUnfocused))
                    )
                    .align_items(Alignment::Center)
            )
            .push(horizontal_rule(1))
            .push(Space::with_height(spacing::LG))
            .push(
                self.create_privacy_status_panel(network_config)
            )
            .push(Space::with_height(spacing::LG))
            .push(
                self.create_privacy_controls_panel()
            )
            .push(Space::with_height(spacing::LG))
            .push(
                self.create_tracking_protection_panel()
            )
            .spacing(spacing::MD)
            .padding(spacing::XL);

        container(dashboard_content)
            .width(Length::Fill)
            .max_width(600)
            .style(theme::Container::Custom(Box::new(GlassStyle)))
            .center_x()
            .into()
    }

    /// Create privacy status panel
    fn create_privacy_status_panel(&self, network_config: &NetworkConfig) -> Element<Message> {
        let status_content = Column::new()
            .push(text("Current Protection Level").size(typography::H3).style(colors::TEXT_PRIMARY))
            .push(Space::with_height(spacing::MD))
            .push(
                container(
                    text(format!("{:?}", network_config.privacy_level))
                        .size(typography::H2)
                        .style(match network_config.privacy_level {
                            PrivacyLevel::Maximum => colors::PRIVACY_MAX,
                            PrivacyLevel::High => colors::PRIVACY_HIGH,
                            PrivacyLevel::Balanced => colors::PRIVACY_BALANCED,
                            PrivacyLevel::Custom => colors::PRIVACY_CUSTOM,
                        })
                )
                .padding(spacing::MD)
                .width(Length::Fill)
                .style(theme::Container::Custom(Box::new(PrivacyIndicatorStyle {
                    privacy_level: network_config.privacy_level,
                })))
            )
            .push(Space::with_height(spacing::MD))
            .push(
                text(match network_config.privacy_level {
                    PrivacyLevel::Maximum => "Maximum protection with advanced anti-fingerprinting",
                    PrivacyLevel::High => "High protection with balanced performance",
                    PrivacyLevel::Balanced => "Balanced protection for everyday browsing",
                    PrivacyLevel::Custom => "Custom privacy configuration",
                })
                .size(typography::SMALL)
                .style(colors::TEXT_SECONDARY)
            )
            .align_items(Alignment::Center);

        container(status_content)
            .width(Length::Fill)
            .padding(spacing::MD)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .into()
    }

    /// Create privacy controls panel
    fn create_privacy_controls_panel(&self) -> Element<Message> {
        let controls_content = Column::new()
            .push(text("Privacy Controls").size(typography::H3).style(colors::TEXT_PRIMARY))
            .push(Space::with_height(spacing::MD))
            .push(
                Column::new()
                    .push(
                        Row::new()
                            .push(checkbox("Block Trackers", true).on_toggle(|_| Message::UI(crate::ui::UIMessage::AddressBarUnfocused)))
                            .push(Space::with_width(Length::Fill))
                            .push(text("Active").size(typography::SMALL).style(colors::PRIVACY_MAX))
                            .align_items(Alignment::Center)
                    )
                    .push(Space::with_height(spacing::MD))
                    .push(
                        Row::new()
                            .push(checkbox("Anti-Fingerprinting", true).on_toggle(|_| Message::UI(crate::ui::UIMessage::AddressBarUnfocused)))
                            .push(Space::with_width(Length::Fill))
                            .push(text("Active").size(typography::SMALL).style(colors::PRIVACY_MAX))
                            .align_items(Alignment::Center)
                    )
                    .push(Space::with_height(spacing::MD))
                    .push(
                        Row::new()
                            .push(checkbox("Private DNS", true).on_toggle(|_| Message::UI(crate::ui::UIMessage::AddressBarUnfocused)))
                            .push(Space::with_width(Length::Fill))
                            .push(text("Active").size(typography::SMALL).style(colors::PRIVACY_MAX))
                            .align_items(Alignment::Center)
                    )
                    .spacing(spacing::MD)
            )
            .spacing(spacing::SM);

        container(controls_content)
            .width(Length::Fill)
            .padding(spacing::MD)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .into()
    }

    /// Create tracking protection panel
    fn create_tracking_protection_panel(&self) -> Element<Message> {
        let tracking_content = Column::new()
            .push(text("Tracking Protection").size(typography::H3).style(colors::TEXT_PRIMARY))
            .push(Space::with_height(spacing::MD))
            .push(
                Row::new()
                    .push(text("🛡️ Trackers Blocked:").size(typography::BODY).style(colors::TEXT_SECONDARY))
                    .push(Space::with_width(Length::Fill))
                    .push(text("1,247").size(typography::BODY).style(colors::PRIVACY_MAX))
                    .align_items(Alignment::Center)
            )
            .push(Space::with_height(spacing::MD))
            .push(
                Row::new()
                    .push(text("🔒 Fingerprinting Attempts:").size(typography::BODY).style(colors::TEXT_SECONDARY))
                    .push(Space::with_width(Length::Fill))
                    .push(text("23").size(typography::BODY).style(colors::WARNING))
                    .align_items(Alignment::Center)
            )
            .push(Space::with_height(spacing::MD))
            .push(
                Row::new()
                    .push(text("🌐 Scripts Blocked:").size(typography::BODY).style(colors::TEXT_SECONDARY))
                    .push(Space::with_width(Length::Fill))
                    .push(text("89").size(typography::BODY).style(colors::PRIVACY_HIGH))
                    .align_items(Alignment::Center)
            )
            .spacing(spacing::MD);

        container(tracking_content)
            .width(Length::Fill)
            .padding(spacing::MD)
            .style(theme::Container::Custom(Box::new(CardStyle)))
            .into()
    }
}

impl Default for CitadelModernUI {
    fn default() -> Self {
        Self::new()
    }
}