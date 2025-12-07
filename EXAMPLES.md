# Citadel Browser UI Integration Examples

This document provides practical examples for integrating and using Citadel Browser's modern UI system.

## Quick Start

### Basic Integration

```rust
use citadel_browser::{
    CitadelBrowser, CitadelModernUI, ThemeManager,
    CitadelTheme, NetworkConfig, PrivacyLevel
};

// Initialize the modern UI
let modern_ui = CitadelModernUI::new();
let theme_manager = ThemeManager::new();

// Create browser with modern UI
let mut browser = CitadelBrowser::new()
    .with_modern_ui(modern_ui)
    .with_theme_manager(theme_manager);

// Set initial theme
browser.set_theme(CitadelTheme::Dark);

// Configure privacy
let mut network_config = NetworkConfig::default();
network_config.privacy_level = PrivacyLevel::High;
browser.set_network_config(network_config);
```

### Running with Demo Mode

```rust
use citadel_browser::ui_demo::CitadelUIDemo;

// Create demo instance
let mut demo = CitadelUIDemo::new();

// In your application loop
fn update_ui(message: Message) -> Command<Message> {
    match message {
        Message::Demo(demo_msg) => {
            demo.update_demo(demo_msg)
        }
        Message::UI(ui_msg) => {
            // Handle regular UI messages
            modern_ui.update(ui_msg)
        }
        // ... other message handling
    }
}

// In your view function
fn view(&self) -> Element<Message> {
    if self.demo_mode {
        demo.view_demo(&self.tab_manager, &self.renderer, &self.viewport_info, self.scroll_state.as_ref())
    } else {
        modern_ui.view(&self.tab_manager, &self.network_config, &self.renderer, &self.viewport_info, self.scroll_state.as_ref())
    }
}
```

## Theme System Usage

### Theme Switching

```rust
use citadel_browser::theme::{CitadelTheme, ThemeManager};

let mut theme_manager = ThemeManager::new();

// Manual theme switching
theme_manager.set_theme(CitadelTheme::Light);
theme_manager.set_theme(CitadelTheme::HighContrast);
theme_manager.set_theme(CitadelTheme::Sepia);

// Create custom theme
let accent_color = iced::Color::from_rgb(0.8, 0.2, 0.5);
theme_manager.set_theme(CitadelTheme::Custom { accent: accent_color });

// Toggle between light and dark
theme_manager.toggle_theme();

// Enable automatic theme switching based on time
theme_manager.set_auto_switch(true);
theme_manager.apply_auto_switch(); // Call this periodically
```

### Theme Integration

```rust
// Apply theme to UI components
fn apply_theme_to_component(theme: CitadelTheme) -> iced::Theme {
    theme.to_iced_theme()
}

// Get current color palette
let palette = theme_manager.current_theme().palette();
let primary_color = palette.primary;
let background_color = palette.background.primary;
```

## Settings Panel Integration

### Basic Settings

```rust
use citadel_browser::settings_panel::{SettingsPanel, SettingsMessage, SettingsCategory};

let mut settings_panel = SettingsPanel::new();

// Handle settings messages
fn handle_settings_message(msg: SettingsMessage) {
    match msg {
        SettingsMessage::ShowSettings => settings_panel.visible = true,
        SettingsMessage::HideSettings => settings_panel.visible = false,
        SettingsMessage::SetPrivacyLevel(level) => {
            network_config.privacy_level = level;
        },
        SettingsMessage::SetTheme(theme) => {
            theme_manager.set_theme(theme);
        },
        // ... handle other settings
    }
}

// Toggle settings panel
fn toggle_settings() -> Message {
    Message::Settings(SettingsMessage::ToggleSettings)
}
```

### Privacy Settings Configuration

```rust
// Configure high privacy settings
fn apply_high_privacy_settings() -> Vec<SettingsMessage> {
    vec![
        SettingsMessage::SetPrivacyLevel(PrivacyLevel::Maximum),
        SettingsMessage::ToggleBlockTrackers(true),
        SettingsMessage::ToggleAntiFingerprinting(true),
        SettingsMessage::TogglePrivateDns(true),
        SettingsMessage::ToggleClearCookiesOnExit(true),
    ]
}

// Apply all settings
for msg in apply_high_privacy_settings() {
    handle_settings_message(msg);
}
```

## Modern UI Components

### Custom Privacy Indicator

```rust
use citadel_browser::ui_modern::{PrivacyIndicatorStyle, colors};

fn create_custom_privacy_indicator(level: PrivacyLevel) -> Element<Message> {
    container(
        button(
            text(format!("🛡️ {:?}", level))
                .size(14)
                .style(match level {
                    PrivacyLevel::Maximum => colors::PRIVACY_MAX,
                    PrivacyLevel::High => colors::PRIVACY_HIGH,
                    PrivacyLevel::Balanced => colors::PRIVACY_BALANCED,
                    PrivacyLevel::Custom => colors::PRIVACY_CUSTOM,
                })
        )
        .padding([6, 12])
        .style(iced::theme::Button::Custom(Box::new(
            PrivacyIndicatorStyle { privacy_level: level }
        )))
        .on_press(Message::OpenPrivacyDashboard)
    )
    .into()
}
```

### Tab Management with Privacy

```rust
use citadel_browser::ui_modern::TabStyle;

fn create_privacy_enhanced_tab(is_active: bool, is_private: bool) -> Element<Message> {
    button(
        container(
            Row::new()
                .push(if is_private {
                    text("🛡️").size(12).style(colors::PRIVACY_MAX)
                } else {
                    text("🌐").size(12).style(colors::TEXT_MUTED)
                })
                .push(text("Private Tab").size(14))
                .push(button("×").size(16).on_press(Message::CloseTab(tab_id)))
                .align_items(Alignment::Center)
        )
        .padding([8, 16])
    )
    .style(iced::theme::Button::Custom(Box::new(TabStyle {
        is_active,
        has_privacy_enhanced: is_private,
        is_loading: false,
    })))
    .on_press(Message::SwitchTab(tab_id))
    .into()
}
```

### Glass Morphism Effects

```rust
use citadel_browser::ui_modern::GlassStyle;

fn create_floating_panel() -> Element<Message> {
    container(
        Column::new()
            .push(text("Floating Panel").size(18))
            .push(text("Content with glass morphism effect").size(14))
            .spacing(8)
            .align_items(Alignment::Center)
    )
    .padding(24)
    .width(Length::Fill)
    .style(iced::theme::Container::Custom(Box::new(GlassStyle)))
    .into()
}
```

## Performance Integration

### Memory Management

```rust
use citadel_browser::performance::{MemoryManager, CleanupPriority};

let mut memory_manager = MemoryManager::new();

// Set memory limits
memory_manager.set_limit_mb(512);
memory_manager.set_cleanup_strategy(CleanupPriority::Low);

// Periodic cleanup
fn perform_memory_cleanup() {
    if memory_manager.should_cleanup() {
        memory_manager.cleanup_inactive_tabs();
        memory_manager.clear_expired_cache();
    }
}

// Memory pressure response
fn handle_memory_pressure() {
    memory_manager.emergency_cleanup();
}
```

### Performance Monitoring

```rust
use citadel_browser::performance::PerformanceMonitor;

let mut performance_monitor = PerformanceMonitor::new();

// Start monitoring
performance_monitor.start_monitoring();

// Get performance report
fn show_performance_metrics() {
    let report = performance_monitor.generate_report();
    println!("Memory usage: {} MB", report.memory_usage_mb);
    println!("Active tabs: {}", report.active_tabs);
    println!("CPU usage: {}%", report.cpu_usage_percent);
}

// Performance recommendations
fn get_optimization_tips() {
    let recommendations = performance_monitor.get_recommendations();
    for tip in recommendations {
        match tip {
            PerformanceRecommendation::ReduceTabCount => {
                println!("Consider closing unused tabs");
            },
            PerformanceRecommendation::ClearCache => {
                println!("Clear browser cache to free memory");
            },
            // ... other recommendations
        }
    }
}
```

## Accessibility Features

### High Contrast Mode

```rust
// Enable high contrast for accessibility
fn enable_accessibility_mode() -> Vec<Message> {
    vec![
        Message::Settings(SettingsMessage::SetTheme(CitadelTheme::HighContrast)),
        Message::Settings(SettingsMessage::SetFontSize(20)),
        Message::Settings(SettingsMessage::ToggleCompactMode(false)),
        Message::Settings(SettingsMessage::ToggleAnimations(false)),
    ]
}
```

### Keyboard Navigation

```rust
// Handle keyboard shortcuts
fn handle_keyboard_shortcut(key: iced::keyboard::Key) -> Option<Message> {
    match key {
        iced::keyboard::Key::Character("c") if modifiers.control() => {
            Some(Message::Settings(SettingsMessage::ShowSettings))
        },
        iced::keyboard::Key::Character("p") if modifiers.control() => {
            Some(Message::OpenPrivacyDashboard)
        },
        iced::keyboard::Key::Character("t") if modifiers.control() => {
            Some(Message::NewTab { tab_type: TabType::Private, initial_url: None })
        },
        // ... more shortcuts
        _ => None,
    }
}
```

## Advanced Customization

### Custom Theme Creation

```rust
use citadel_browser::theme::Palette;
use iced::Color;

fn create_custom_theme() -> Palette {
    Palette::custom(Color::from_rgb(0.2, 0.6, 0.8))
}

fn apply_brand_colors() {
    let brand_primary = Color::from_rgb(0.1, 0.3, 0.6);
    let brand_secondary = Color::from_rgb(0.6, 0.3, 0.1);

    let custom_palette = Palette {
        primary: brand_primary,
        secondary: brand_secondary,
        // ... configure other colors
        ..Palette::dark()
    };
}
```

### Component Customization

```rust
// Custom button style
struct CustomButtonStyle {
    is_privacy_focused: bool,
}

impl iced::widget::button::StyleSheet for CustomButtonStyle {
    type Style = iced::Theme;

    fn active(&self, style: &Self::Style) -> iced::widget::button::Appearance {
        iced::widget::button::Appearance {
            background: if self.is_privacy_focused {
                Some(iced::Background::Color(colors::PRIVACY_HIGH))
            } else {
                Some(iced::Background::Color(colors::PRIMARY))
            },
            border_radius: radius::MD.into(),
            // ... other styling
        }
    }
}
```

## Testing and Debugging

### UI Testing

```rust
// Test UI component rendering
#[test]
fn test_privacy_indicator_rendering() {
    let indicator = create_custom_privacy_indicator(PrivacyLevel::Maximum);
    // Assert appearance and functionality
}

// Test theme switching
#[test]
fn test_theme_persistence() {
    let mut theme_manager = ThemeManager::new();
    theme_manager.set_theme(CitadelTheme::Light);
    assert_eq!(theme_manager.current_theme(), CitadelTheme::Light);
}
```

### Performance Profiling

```rust
// Profile UI rendering
fn profile_ui_rendering() {
    let start = std::time::Instant::now();
    let _ui = modern_ui.view(&tab_manager, &network_config, &renderer, &viewport_info, None);
    let duration = start.elapsed();
    println!("UI render time: {:?}", duration);
}
```

## Best Practices

### 1. Performance Optimization

```rust
// Use lazy loading for heavy components
fn create_lazy_component() -> Element<Message> {
    if self.should_load_component {
        create_heavy_component()
    } else {
        create_loading_placeholder()
    }
}

// Cache expensive computations
struct CachedUI {
    cached_content: Option<Element<Message>>,
    last_update: std::time::Instant,
}

impl CachedUI {
    fn get_or_create(&mut self, recreate: bool) -> Element<Message> {
        if self.cached_content.is_none() || recreate {
            self.cached_content = Some(create_expensive_content());
            self.last_update = std::time::Instant::now();
        }
        self.cached_content.clone().unwrap()
    }
}
```

### 2. Error Handling

```rust
// Graceful error handling for UI components
fn safe_ui_render() -> Element<Message> {
    match create_ui_component() {
        Ok(component) => component,
        Err(error) => create_error_display(error),
    }
}

fn create_error_display(error: impl std::fmt::Display) -> Element<Message> {
    container(
        Column::new()
            .push(text("⚠️ UI Error").size(20).style(colors::ERROR))
            .push(text(format!("{}", error)).size(14).style(colors::TEXT_MUTED))
            .spacing(8)
            .align_items(Alignment::Center)
    )
    .padding(24)
    .style(iced::theme::Container::Custom(Box::new(GlassStyle)))
    .into()
}
```

### 3. Responsive Design

```rust
// Adapt UI based on viewport size
fn create_responsive_layout(viewport_width: f32) -> Element<Message> {
    if viewport_width < 768.0 {
        create_mobile_layout()
    } else if viewport_width < 1200.0 {
        create_tablet_layout()
    } else {
        create_desktop_layout()
    }
}
```

## Integration Checklist

- [ ] Initialize `CitadelModernUI` with app
- [ ] Set up `ThemeManager` for theme switching
- [ ] Configure `SettingsPanel` for preferences
- [ ] Implement privacy indicators and badges
- [ ] Add keyboard navigation shortcuts
- [ ] Enable accessibility features
- [ ] Set up performance monitoring
- [ ] Configure memory management
- [ ] Add error handling and fallbacks
- [ ] Test responsive design
- [ ] Verify accessibility compliance

## Migration from Legacy UI

### Step 1: Add Modern UI
```rust
// Replace legacy UI initialization
let modern_ui = CitadelModernUI::new();
```

### Step 2: Update Message Handling
```rust
// Add modern UI message handling
enum Message {
    // Legacy messages...
    UI(ModernUIMessage),
    Settings(SettingsMessage),
    Demo(DemoMessage),
}
```

### Step 3: Update View Function
```rust
// Use modern UI in view function
fn view(&self) -> Element<Message> {
    self.modern_ui.view(&self.tab_manager, &self.network_config, &self.renderer, &self.viewport_info, self.scroll_state.as_ref())
}
```

### Step 4: Configure Themes
```rust
// Add theme management
let theme_manager = ThemeManager::new();
browser.set_theme_manager(theme_manager);
```

This comprehensive guide should help you effectively integrate and customize Citadel Browser's modern UI system. The examples cover everything from basic setup to advanced customization and performance optimization.