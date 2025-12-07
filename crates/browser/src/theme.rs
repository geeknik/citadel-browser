//! Modern theme system for Citadel Browser
//!
//! This module provides a comprehensive theming system that supports
//! light/dark modes, accessibility features, and customizable accents.

use iced::{Theme, Color};
use crate::ui_modern::{colors, typography, spacing, radius};

/// Citadel Browser theme variants
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CitadelTheme {
    /// Default dark theme with privacy focus
    Dark,
    /// Light theme for daytime use
    Light,
    /// High contrast accessibility theme
    HighContrast,
    /// Sepia theme for reduced eye strain
    Sepia,
    /// Custom theme with user-defined colors
    Custom { accent: Color },
}

impl CitadelTheme {
    /// Get the appropriate palette for this theme
    pub fn palette(self) -> Palette {
        match self {
            CitadelTheme::Dark => Palette::dark(),
            CitadelTheme::Light => Palette::light(),
            CitadelTheme::HighContrast => Palette::high_contrast(),
            CitadelTheme::Sepia => Palette::sepia(),
            CitadelTheme::Custom { accent } => Palette::custom(accent),
        }
    }

    /// Convert to Iced theme
    pub fn to_iced_theme(self) -> Theme {
        match self {
            CitadelTheme::Dark => Theme::Dark,
            CitadelTheme::Light => Theme::Light,
            CitadelTheme::HighContrast => Theme::Dark, // Use dark base with custom styling
            CitadelTheme::Sepia => Theme::Light, // Use light base with custom colors
            CitadelTheme::Custom { .. } => Theme::Dark, // Use dark base for custom
        }
    }
}

/// Color palette for different themes
#[derive(Debug, Clone)]
pub struct Palette {
    /// Primary accent color
    pub primary: Color,
    /// Secondary accent color
    pub secondary: Color,
    /// Background colors
    pub background: BackgroundColors,
    /// Text colors
    pub text: TextColors,
    /// Semantic colors
    pub semantic: SemanticColors,
    /// Border colors
    pub border: BorderColors,
    /// Shadow colors
    pub shadow: ShadowColors,
}

/// Background color variations
#[derive(Debug, Clone)]
pub struct BackgroundColors {
    pub primary: Color,
    pub secondary: Color,
    pub tertiary: Color,
    pub overlay: Color,
    pub glass: Color,
}

/// Text color variations
#[derive(Debug, Clone)]
pub struct TextColors {
    pub primary: Color,
    pub secondary: Color,
    pub tertiary: Color,
    pub inverse: Color,
    pub link: Color,
}

/// Semantic colors for status and feedback
#[derive(Debug, Clone)]
pub struct SemanticColors {
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,
    pub privacy: PrivacyColors,
}

/// Privacy-specific colors
#[derive(Debug, Clone)]
pub struct PrivacyColors {
    pub maximum: Color,
    pub high: Color,
    pub balanced: Color,
    pub custom: Color,
    pub active: Color,
}

/// Border color variations
#[derive(Debug, Clone)]
pub struct BorderColors {
    pub primary: Color,
    pub secondary: Color,
    pub focus: Color,
    pub subtle: Color,
    pub accent: Color,
}

/// Shadow colors for depth and elevation
#[derive(Debug, Clone)]
pub struct ShadowColors {
    pub light: Color,
    pub medium: Color,
    pub heavy: Color,
    pub accent: Color,
}

impl Palette {
    /// Dark theme palette
    pub fn dark() -> Self {
        Self {
            primary: colors::PRIMARY,
            secondary: colors::PRIMARY_LIGHT,
            background: BackgroundColors {
                primary: colors::BACKGROUND_DARK,
                secondary: colors::BACKGROUND_CARD,
                tertiary: colors::BACKGROUND_HOVER,
                overlay: Color::from_rgba(0.0, 0.0, 0.0, 0.50),
                glass: colors::GLASS_OVERLAY,
            },
            text: TextColors {
                primary: colors::TEXT_PRIMARY,
                secondary: colors::TEXT_SECONDARY,
                tertiary: colors::TEXT_MUTED,
                inverse: Color::from_rgb(0.08, 0.08, 0.12),
                link: colors::PRIMARY_LIGHT,
            },
            semantic: SemanticColors {
                success: colors::SUCCESS,
                warning: colors::WARNING,
                error: colors::ERROR,
                info: colors::INFO,
                privacy: PrivacyColors {
                    maximum: colors::PRIVACY_MAX,
                    high: colors::PRIVACY_HIGH,
                    balanced: colors::PRIVACY_BALANCED,
                    custom: colors::PRIVACY_CUSTOM,
                    active: colors::PRIVACY_HIGH,
                },
            },
            border: BorderColors {
                primary: colors::BORDER_SUBTLE,
                secondary: colors::BORDER_SUBTLE,
                focus: colors::BORDER_FOCUS,
                subtle: Color::from_rgb(0.15, 0.15, 0.20),
                accent: colors::PRIMARY,
            },
            shadow: ShadowColors {
                light: Color::from_rgba(0.0, 0.0, 0.0, 0.10),
                medium: Color::from_rgba(0.0, 0.0, 0.0, 0.20),
                heavy: Color::from_rgba(0.0, 0.0, 0.0, 0.30),
                accent: Color::from_rgba(0.05, 0.45, 0.90, 0.20),
            },
        }
    }

    /// Light theme palette
    pub fn light() -> Self {
        Self {
            primary: Color::from_rgb(0.05, 0.45, 0.90),
            secondary: Color::from_rgb(0.15, 0.55, 1.0),
            background: BackgroundColors {
                primary: Color::from_rgb(0.98, 0.98, 1.0),
                secondary: Color::from_rgb(0.95, 0.95, 0.97),
                tertiary: Color::from_rgb(0.92, 0.92, 0.95),
                overlay: Color::from_rgba(0.0, 0.0, 0.0, 0.30),
                glass: Color::from_rgba(1.0, 1.0, 1.0, 0.70),
            },
            text: TextColors {
                primary: Color::from_rgb(0.05, 0.05, 0.15),
                secondary: Color::from_rgb(0.35, 0.35, 0.45),
                tertiary: Color::from_rgb(0.55, 0.55, 0.60),
                inverse: Color::from_rgb(0.98, 0.98, 1.0),
                link: Color::from_rgb(0.0, 0.35, 0.80),
            },
            semantic: SemanticColors {
                success: Color::from_rgb(0.0, 0.60, 0.20),
                warning: Color::from_rgb(0.80, 0.50, 0.0),
                error: Color::from_rgb(0.80, 0.20, 0.20),
                info: Color::from_rgb(0.0, 0.50, 0.70),
                privacy: PrivacyColors {
                    maximum: Color::from_rgb(0.0, 0.65, 0.15),
                    high: Color::from_rgb(0.0, 0.50, 0.70),
                    balanced: Color::from_rgb(0.80, 0.50, 0.0),
                    custom: Color::from_rgb(0.40, 0.40, 0.40),
                    active: Color::from_rgb(0.0, 0.50, 0.70),
                },
            },
            border: BorderColors {
                primary: Color::from_rgb(0.80, 0.80, 0.85),
                secondary: Color::from_rgb(0.85, 0.85, 0.90),
                focus: Color::from_rgb(0.25, 0.55, 0.90),
                subtle: Color::from_rgb(0.90, 0.90, 0.93),
                accent: Color::from_rgb(0.05, 0.45, 0.90),
            },
            shadow: ShadowColors {
                light: Color::from_rgba(0.0, 0.0, 0.0, 0.05),
                medium: Color::from_rgba(0.0, 0.0, 0.0, 0.10),
                heavy: Color::from_rgba(0.0, 0.0, 0.0, 0.15),
                accent: Color::from_rgba(0.05, 0.45, 0.90, 0.15),
            },
        }
    }

    /// High contrast theme palette
    pub fn high_contrast() -> Self {
        Self {
            primary: Color::from_rgb(0.0, 0.6, 1.0),
            secondary: Color::from_rgb(0.0, 0.8, 1.0),
            background: BackgroundColors {
                primary: Color::BLACK,
                secondary: Color::from_rgb(0.05, 0.05, 0.05),
                tertiary: Color::from_rgb(0.10, 0.10, 0.10),
                overlay: Color::from_rgba(1.0, 1.0, 1.0, 0.90),
                glass: Color::from_rgba(0.0, 0.0, 0.0, 0.80),
            },
            text: TextColors {
                primary: Color::WHITE,
                secondary: Color::from_rgb(0.9, 0.9, 0.9),
                tertiary: Color::from_rgb(0.7, 0.7, 0.7),
                inverse: Color::BLACK,
                link: Color::from_rgb(0.4, 0.8, 1.0),
            },
            semantic: SemanticColors {
                success: Color::from_rgb(0.0, 1.0, 0.4),
                warning: Color::from_rgb(1.0, 0.8, 0.0),
                error: Color::from_rgb(1.0, 0.3, 0.3),
                info: Color::from_rgb(0.4, 0.8, 1.0),
                privacy: PrivacyColors {
                    maximum: Color::from_rgb(0.0, 1.0, 0.4),
                    high: Color::from_rgb(0.0, 0.8, 1.0),
                    balanced: Color::from_rgb(1.0, 0.8, 0.0),
                    custom: Color::from_rgb(0.7, 0.7, 0.7),
                    active: Color::from_rgb(0.0, 0.8, 1.0),
                },
            },
            border: BorderColors {
                primary: Color::WHITE,
                secondary: Color::from_rgb(0.8, 0.8, 0.8),
                focus: Color::from_rgb(0.0, 0.8, 1.0),
                subtle: Color::from_rgb(0.3, 0.3, 0.3),
                accent: Color::from_rgb(0.0, 0.8, 1.0),
            },
            shadow: ShadowColors {
                light: Color::from_rgba(0.0, 0.0, 0.0, 0.0),
                medium: Color::from_rgba(0.0, 0.0, 0.0, 0.0),
                heavy: Color::from_rgba(0.0, 0.0, 0.0, 0.0),
                accent: Color::from_rgba(0.0, 0.8, 1.0, 0.0),
            },
        }
    }

    /// Sepia theme palette for reduced eye strain
    pub fn sepia() -> Self {
        Self {
            primary: Color::from_rgb(0.4, 0.3, 0.1),
            secondary: Color::from_rgb(0.6, 0.4, 0.2),
            background: BackgroundColors {
                primary: Color::from_rgb(0.98, 0.94, 0.87),
                secondary: Color::from_rgb(0.94, 0.90, 0.82),
                tertiary: Color::from_rgb(0.90, 0.85, 0.75),
                overlay: Color::from_rgba(0.4, 0.3, 0.1, 0.30),
                glass: Color::from_rgba(0.98, 0.94, 0.87, 0.70),
            },
            text: TextColors {
                primary: Color::from_rgb(0.25, 0.15, 0.05),
                secondary: Color::from_rgb(0.40, 0.30, 0.15),
                tertiary: Color::from_rgb(0.55, 0.45, 0.30),
                inverse: Color::from_rgb(0.98, 0.94, 0.87),
                link: Color::from_rgb(0.5, 0.3, 0.1),
            },
            semantic: SemanticColors {
                success: Color::from_rgb(0.4, 0.6, 0.2),
                warning: Color::from_rgb(0.8, 0.6, 0.2),
                error: Color::from_rgb(0.8, 0.3, 0.2),
                info: Color::from_rgb(0.4, 0.5, 0.6),
                privacy: PrivacyColors {
                    maximum: Color::from_rgb(0.4, 0.6, 0.2),
                    high: Color::from_rgb(0.3, 0.5, 0.6),
                    balanced: Color::from_rgb(0.8, 0.6, 0.2),
                    custom: Color::from_rgb(0.5, 0.4, 0.3),
                    active: Color::from_rgb(0.3, 0.5, 0.6),
                },
            },
            border: BorderColors {
                primary: Color::from_rgb(0.70, 0.60, 0.50),
                secondary: Color::from_rgb(0.80, 0.70, 0.60),
                focus: Color::from_rgb(0.4, 0.3, 0.1),
                subtle: Color::from_rgb(0.85, 0.75, 0.65),
                accent: Color::from_rgb(0.4, 0.3, 0.1),
            },
            shadow: ShadowColors {
                light: Color::from_rgba(0.4, 0.3, 0.1, 0.05),
                medium: Color::from_rgba(0.4, 0.3, 0.1, 0.10),
                heavy: Color::from_rgba(0.4, 0.3, 0.1, 0.15),
                accent: Color::from_rgba(0.4, 0.3, 0.1, 0.15),
            },
        }
    }

    /// Custom theme with user-defined accent color
    pub fn custom(accent: Color) -> Self {
        let mut palette = Self::dark();
        palette.primary = accent;
        palette.secondary = Color::from_rgb(
            (accent.r * 0.8).max(0.0),
            (accent.g * 0.8).max(0.0),
            (accent.b * 0.8).max(0.0),
        );
        palette.border.accent = accent;
        palette.shadow.accent = Color::from_rgba(accent.r, accent.g, accent.b, 0.20);
        palette
    }
}

/// Theme manager for handling theme switching and persistence
pub struct ThemeManager {
    current_theme: CitadelTheme,
    auto_switch: bool,
    follow_system: bool,
}

impl ThemeManager {
    /// Create a new theme manager
    pub fn new() -> Self {
        Self {
            current_theme: CitadelTheme::Dark,
            auto_switch: false,
            follow_system: true,
        }
    }

    /// Get the current theme
    pub fn current_theme(&self) -> CitadelTheme {
        self.current_theme
    }

    /// Set the theme
    pub fn set_theme(&mut self, theme: CitadelTheme) {
        self.current_theme = theme;
    }

    /// Toggle between light and dark themes
    pub fn toggle_theme(&mut self) {
        self.current_theme = match self.current_theme {
            CitadelTheme::Dark => CitadelTheme::Light,
            CitadelTheme::Light => CitadelTheme::Dark,
            other => other, // Keep custom themes unchanged
        };
    }

    /// Enable/disable automatic theme switching based on time
    pub fn set_auto_switch(&mut self, enabled: bool) {
        self.auto_switch = enabled;
    }

    /// Check if theme should auto-switch based on system time
    pub fn should_switch_theme(&self) -> bool {
        if !self.auto_switch {
            return false;
        }

        use chrono::{Local, Timelike};
        let hour = Local::now().hour();

        // Switch to light theme between 6 AM and 6 PM
        matches!(self.current_theme, CitadelTheme::Dark) && hour >= 6 && hour < 18 ||
        matches!(self.current_theme, CitadelTheme::Light) && (hour < 6 || hour >= 18)
    }

    /// Apply automatic theme switching if enabled
    pub fn apply_auto_switch(&mut self) {
        if self.auto_switch && self.should_switch_theme() {
            self.toggle_theme();
        }
    }
}

impl Default for ThemeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Extension trait for styling Iced components with Citadel theme
pub trait CitadelStyling {
    /// Apply privacy-themed styling
    fn privacy_style(&self, level: citadel_networking::PrivacyLevel) -> theme::Button;

    /// Apply subtle button styling
    fn subtle_style(&self) -> theme::Button;

    /// Apply glass morphism styling
    fn glass_style(&self) -> theme::Container;
}

/// Button styling extensions
impl CitadelStyling for theme::Button {
    fn privacy_style(&self, level: citadel_networking::PrivacyLevel) -> theme::Button {
        match level {
            citadel_networking::PrivacyLevel::Maximum => theme::Button::Primary,
            citadel_networking::PrivacyLevel::High => theme::Button::Secondary,
            citadel_networking::PrivacyLevel::Balanced => theme::Button::Positive,
            citadel_networking::PrivacyLevel::Custom => theme::Button::Destructive,
        }
    }

    fn subtle_style(&self) -> theme::Button {
        theme::Button::Text
    }

    fn glass_style(&self) -> theme::Container {
        theme::Container::Transparent
    }
}

/// Container styling extensions
impl CitadelStyling for theme::Container {
    fn privacy_style(&self, _level: citadel_networking::PrivacyLevel) -> theme::Button {
        theme::Button::Primary // Not applicable, but required by trait
    }

    fn subtle_style(&self) -> theme::Button {
        theme::Button::Text // Not applicable, but required by trait
    }

    fn glass_style(&self) -> theme::Container {
        theme::Container::Transparent // Will be overridden by custom styles
    }
}

// Re-export theme components
pub use iced::theme::{self, Palette as IcedPalette};