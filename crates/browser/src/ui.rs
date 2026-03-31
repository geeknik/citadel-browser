use std::sync::Arc;
use iced::{
    widget::{button, container, text, text_input, scrollable, Space, Column, Row},
    Element, Length, Color, Alignment, theme, Background,
    widget::container::{Appearance, StyleSheet},
};
use citadel_tabs::{SendSafeTabManager as TabManager};
use crate::app::{Message, ViewportInfo, ScrollState, ZoomLevel};
use crate::renderer::CitadelRenderer;
use citadel_networking::{NetworkConfig, PrivacyLevel};
use citadel_security::{PrivacyStats, PrivacyEvent};

/// Custom style for the info bar
#[derive(Clone, Copy, Debug)]
struct InfoBarStyle;

impl StyleSheet for InfoBarStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> Appearance {
        Appearance {
            background: Some(Background::Color(Color::from_rgb(0.1, 0.1, 0.15))),
            border: iced::Border {
                color: Color::from_rgb(0.2, 0.2, 0.3),
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        }
    }
}

/// Custom style for the privacy scoreboard panel
#[derive(Clone, Copy, Debug)]
struct PrivacyPanelStyle;

impl StyleSheet for PrivacyPanelStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> Appearance {
        Appearance {
            background: Some(Background::Color(Color::from_rgb(0.06, 0.08, 0.12))),
            border: iced::Border {
                color: Color::from_rgb(0.0, 0.4, 0.3),
                width: 1.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        }
    }
}

/// Custom style for privacy stat rows
#[derive(Clone, Copy, Debug)]
struct PrivacyStatRowStyle;

impl StyleSheet for PrivacyStatRowStyle {
    type Style = iced::Theme;

    fn appearance(&self, _style: &Self::Style) -> Appearance {
        Appearance {
            background: Some(Background::Color(Color::from_rgb(0.08, 0.10, 0.15))),
            border: iced::Border {
                color: Color::from_rgb(0.15, 0.15, 0.22),
                width: 1.0,
                radius: 3.0.into(),
            },
            ..Default::default()
        }
    }
}

/// Main UI state and components
#[derive(Debug, Clone)]
pub struct CitadelUI {
    /// Current URL in the address bar
    address_bar_value: String,
    /// Whether the address bar is focused
    address_bar_focused: bool,
}

/// Messages specific to the UI layer
#[derive(Debug, Clone)]
pub enum UIMessage {
    /// Address bar value changed
    AddressBarChanged(String),
    /// Address bar submitted (Enter pressed)
    AddressBarSubmitted,
    /// Address bar focused
    #[allow(dead_code)] // Will be used when implementing address bar focus handling
    AddressBarFocused,
    /// Address bar unfocused
    #[allow(dead_code)] // Will be used when implementing address bar focus handling
    AddressBarUnfocused,
    /// Zoom level changed from UI
    #[allow(dead_code)] // Will be used when implementing zoom controls
    ZoomChanged(ZoomLevel),
    /// Scroll position changed from UI
    #[allow(dead_code)] // Will be used when implementing scroll controls
    ScrollChanged { x: f32, y: f32 },
}

impl CitadelUI {
    /// Create a new UI state
    pub fn new() -> Self {
        Self {
            address_bar_value: String::new(),
            address_bar_focused: false,
        }
    }
    
    /// Get the current address bar value
    pub fn address_bar_value(&self) -> &str {
        &self.address_bar_value
    }

    /// Update the UI state based on messages
    pub fn update(&mut self, message: UIMessage) -> iced::Command<Message> {
        match message {
            UIMessage::AddressBarChanged(value) => {
                self.address_bar_value = value;
            }
            UIMessage::AddressBarSubmitted => {
                if !self.address_bar_value.trim().is_empty() {
                    let url = self.address_bar_value.clone(); // Clone to avoid borrowing issues
                    return iced::Command::perform(
                        async move {},
                        move |_| Message::Navigate(url),
                    );
                }
            }
            UIMessage::AddressBarFocused => {
                self.address_bar_focused = true;
            }
            UIMessage::AddressBarUnfocused => {
                self.address_bar_focused = false;
            }
            UIMessage::ZoomChanged(_zoom_level) => {
                // Zoom changes are handled at the app level
                // This is here for completeness
            }
            UIMessage::ScrollChanged { x: _, y: _ } => {
                // Scroll changes are handled at the app level
                // This is here for completeness
            }
        }
        iced::Command::none()
    }

    /// Create the main UI view
    pub fn view<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        network_config: &NetworkConfig,
        renderer: &'a CitadelRenderer,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
        privacy_stats: &PrivacyStats,
        privacy_panel_expanded: bool,
    ) -> Element<'a, Message> {
        let toolbar = self.create_toolbar(tab_manager, network_config, viewport_info);
        let main_content = self.create_content_area(tab_manager, renderer, viewport_info, scroll_state);
        let privacy_panel = Self::privacy_scoreboard_view(privacy_stats, privacy_panel_expanded);

        let body = Row::new()
            .push(
                container(main_content)
                    .width(Length::FillPortion(4))
                    .height(Length::Fill),
            )
            .push(
                container(privacy_panel)
                    .width(Length::FillPortion(1))
                    .height(Length::Fill),
            )
            .spacing(0);

        let content = Column::new()
            .push(toolbar)
            .push(body)
            .spacing(0);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
    
    /// Create the browser toolbar
    fn create_toolbar(
        &self,
        _tab_manager: &Arc<TabManager>,
        network_config: &NetworkConfig,
        viewport_info: &ViewportInfo,
    ) -> Element<Message> {
        let navigation_buttons = Row::new()
            .push(button("←").padding(8))
            .push(button("→").padding(8))
            .push(button("⟳").padding(8))
            .spacing(4);
        
        let address_bar = text_input("Enter URL...", &self.address_bar_value)
            .on_input(|value| Message::UI(UIMessage::AddressBarChanged(value)))
            .on_submit(Message::UI(UIMessage::AddressBarSubmitted))
            .padding(8)
            .width(Length::Fill);
        
        let privacy_indicator = self.create_privacy_indicator(network_config);
        
        let zoom_controls = self.create_zoom_controls(viewport_info);
        
        let new_tab_button = button("+")
            .padding(8)
            .on_press(Message::NewTab { 
                tab_type: citadel_tabs::TabType::Ephemeral, 
                initial_url: None 
            });
        
        let toolbar = Row::new()
            .push(navigation_buttons)
            .push(Space::with_width(8))
            .push(address_bar)
            .push(Space::with_width(8))
            .push(zoom_controls)
            .push(Space::with_width(8))
            .push(privacy_indicator)
            .push(Space::with_width(8))
            .push(new_tab_button)
            .align_items(Alignment::Center)
            .padding(8);
        
        container(toolbar)
            .width(Length::Fill)
            .into()
    }

    /// Create privacy level indicator
    fn create_privacy_indicator(&self, network_config: &NetworkConfig) -> Element<Message> {
        let (indicator_text, indicator_color) = match network_config.privacy_level {
            PrivacyLevel::Maximum => ("🛡️ MAX", Color::from_rgb(0.0, 0.8, 0.0)),
            PrivacyLevel::High => ("🛡️ HIGH", Color::from_rgb(0.0, 0.6, 0.8)),
            PrivacyLevel::Balanced => ("🛡️ BAL", Color::from_rgb(0.8, 0.6, 0.0)),
            PrivacyLevel::Custom => ("🛡️ CUSTOM", Color::from_rgb(0.6, 0.6, 0.6)),
        };
        
        button(text(indicator_text).style(indicator_color))
        .padding(6)
        .into()
    }
    
    /// Create the main content area
    fn create_content_area<'a>(
        &'a self, 
        tab_manager: &Arc<TabManager>, 
        renderer: &'a CitadelRenderer, 
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        let tabs_bar = self.create_tabs_bar(tab_manager);
        let page_content = self.create_page_content(tab_manager, renderer, viewport_info, scroll_state);
        
        Column::new()
            .push(tabs_bar)
            .push(page_content)
            .spacing(0)
            .into()
    }
    
    /// Create the tabs bar
    fn create_tabs_bar(&self, tab_manager: &Arc<TabManager>) -> Element<Message> {
        let tab_states = tab_manager.get_tab_states();
        
        let mut tab_buttons = Row::new().spacing(2);
        
        for tab_state in tab_states {
            let tab_title = if tab_state.title.is_empty() {
                "New Tab".to_string()
            } else {
                tab_state.title.clone()
            };
            
            let tab_button = button(
                Row::new()
                    .push(text(tab_title).width(Length::Fixed(150.0)))
                    .push(button("×")
                        .padding(2)
                        .on_press(Message::CloseTab(tab_state.id)))
                    .align_items(Alignment::Center)
            )
            .padding(8)
            .on_press(Message::SwitchTab(tab_state.id));
            
            tab_buttons = tab_buttons.push(tab_button);
        }
        
        container(
            scrollable(tab_buttons)
                .direction(scrollable::Direction::Horizontal(
                    scrollable::Properties::default()
                ))
        )
        .width(Length::Fill)
        .padding(4)

        .into()
    }
    
    /// Create the page content area
    fn create_page_content<'a>(
        &'a self, 
        tab_manager: &Arc<TabManager>, 
        renderer: &'a CitadelRenderer, 
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        let tab_states = tab_manager.get_tab_states();
        
        if let Some(active_tab) = tab_states.iter().find(|tab| tab.is_active) {
            // Render content based on the page content state
            match &active_tab.content {
                citadel_tabs::PageContent::Loading { url } => {
                    let content = Column::new()
                        .push(Space::with_height(50))
                        .push(text("🔄 Loading Page...")
                            .size(20)
                            .style(Color::from_rgb(0.0, 0.6, 0.8)))
                        .push(Space::with_height(10))
                        .push(text(format!("URL: {}", url))
                            .size(14)
                            .style(Color::from_rgb(0.7, 0.7, 0.7)))
                        .push(Space::with_height(20))
                        .push(text("🛡️ ZKVM Isolation Preparing...")
                            .size(12)
                            .style(Color::from_rgb(0.0, 0.6, 0.8)))
                        .push(Space::with_height(10))
                        .push(text("Establishing secure connection and parsing content")
                            .size(11)
                            .style(Color::from_rgb(0.5, 0.5, 0.5)))
                        .align_items(Alignment::Center);
                    
                    container(content)
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .center_x()
                        .into()
                }
                citadel_tabs::PageContent::Loaded { 
                    url: _, 
                    title: _,
                    content: _,
                    element_count,
                    size_bytes 
                } => {
                    // Get the actual rendered content from the renderer
                    let rendered_content = renderer.render();
                    
                    // Create a comprehensive header with scroll info and zoom level
                    let mut header_elements = Row::new()
                        .push(text(format!("📊 {} elements", element_count))
                            .size(11)
                            .style(Color::from_rgb(0.6, 0.6, 0.6)))
                        .push(text(" • ").size(11).style(Color::from_rgb(0.5, 0.5, 0.5)))
                        .push(text(format!("{} bytes", size_bytes))
                            .size(11)
                            .style(Color::from_rgb(0.6, 0.6, 0.6)))
                        .push(text(" • ").size(11).style(Color::from_rgb(0.5, 0.5, 0.5)))
                        .push(text(format!("🔍 {}%", viewport_info.zoom_level.as_percentage()))
                            .size(11)
                            .style(Color::from_rgb(0.2, 0.6, 0.9)))
                        .spacing(0)
                        .align_items(Alignment::Center);
                    
                    // Add scroll position if available
                    if let Some(scroll) = scroll_state {
                        header_elements = header_elements
                            .push(text(" • ").size(11).style(Color::from_rgb(0.5, 0.5, 0.5)))
                            .push(text(format!("📍 ({:.0}, {:.0})", scroll.x, scroll.y))
                                .size(11)
                                .style(Color::from_rgb(0.6, 0.6, 0.6)));
                    }
                    
                    header_elements = header_elements
                        .push(text(" • ").size(11).style(Color::from_rgb(0.5, 0.5, 0.5)))
                        .push(text("🛡️ ZKVM Active")
                            .size(11)
                            .style(Color::from_rgb(0.0, 0.6, 0.8)));
                    
                    // Create scrollable content with viewport-aware rendering
                    let scrollable_content = self.create_scrollable_content(
                        rendered_content, 
                        viewport_info, 
                        scroll_state
                    );
                    
                    // Prioritize the rendered content with comprehensive header
                    let full_content = Column::new()
                        .push(container(header_elements)
                            .width(Length::Fill)
                            .padding([5, 10, 5, 10])
                            .style(theme::Container::Custom(Box::new(InfoBarStyle))))
                        .push(scrollable_content)
                        .spacing(0);
                    
                    container(full_content)
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .into()
                }
                citadel_tabs::PageContent::Error { url, error } => {
                    let content = Column::new()
                        .push(Space::with_height(50))
                        .push(text("❌ Failed to Load Page")
                            .size(24)
                            .style(Color::from_rgb(1.0, 0.3, 0.3)))
                        .push(Space::with_height(10))
                        .push(text(format!("URL: {}", url))
                            .size(14)
                            .style(Color::from_rgb(0.7, 0.7, 0.7)))
                        .push(Space::with_height(10))
                        .push(text(format!("Error: {}", error))
                            .size(12)
                            .style(Color::from_rgb(0.8, 0.4, 0.4)))
                        .push(Space::with_height(20))
                        .push(text("🛡️ ZKVM Protection Active")
                            .size(12)
                            .style(Color::from_rgb(0.0, 0.6, 0.8)))
                        .push(Space::with_height(10))
                        .push(text("Your browser prevented potentially harmful content from loading")
                            .size(11)
                            .style(Color::from_rgb(0.5, 0.5, 0.5)))
                        .align_items(Alignment::Center);
                    
                    container(content)
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .center_x()
                        .into()
                }
                citadel_tabs::PageContent::Empty => {
                    let content = Column::new()
                        .push(Space::with_height(50))
                        .push(text("Empty Tab")
                            .size(20)
                            .style(Color::from_rgb(0.6, 0.6, 0.6)))
                        .push(Space::with_height(10))
                        .push(text("Navigate to a URL to load content")
                            .size(14)
                            .style(Color::from_rgb(0.5, 0.5, 0.5)))
                        .push(Space::with_height(20))
                        .push(text("🛡️ ZKVM Isolation Ready")
                            .size(12)
                            .style(Color::from_rgb(0.0, 0.6, 0.8)))
                        .align_items(Alignment::Center);
                    
                    container(content)
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .center_x()
                        .into()
                }
            }
        } else {
            container(
                Column::new()
                    .push(Space::with_height(50))
                    .push(text(format!("Welcome to Citadel Browser v{}", env!("CARGO_PKG_VERSION")))
                        .size(32)
                        .style(Color::from_rgb(0.8, 0.8, 0.8)))
                    .push(Space::with_height(10))
                    .push(text("Privacy-First Web Browser")
                        .size(16)
                        .style(Color::from_rgb(0.6, 0.6, 0.6)))
                    .push(Space::with_height(20))
                    .push(text("⚠️ ALPHA SOFTWARE - USE AT YOUR OWN RISK ⚠️")
                        .size(14)
                        .style(Color::from_rgb(1.0, 0.6, 0.0)))
                    .push(Space::with_height(10))
                    .push(text("This is experimental software not intended for production use")
                        .size(12)
                        .style(Color::from_rgb(0.8, 0.4, 0.4)))
                    .push(Space::with_height(30))
                    .push(text("Navigate by entering a URL in the address bar above")
                        .size(14)
                        .style(Color::from_rgb(0.6, 0.6, 0.6)))
                    .push(Space::with_height(10))
                    .push(text("🛡️ Zero-Knowledge Virtual Machine tab isolation enabled")
                        .size(12)
                        .style(Color::from_rgb(0.0, 0.6, 0.8)))
                    .align_items(Alignment::Center)
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .into()
        }
    }
    
    /// Create zoom controls for the toolbar
    fn create_zoom_controls(&self, viewport_info: &ViewportInfo) -> Element<Message> {
        let zoom_out_button = button("🔍−")
            .padding(4)
            .on_press(Message::ZoomOut)
            .style(theme::Button::Secondary);
            
        let zoom_level_text = text(format!("{}%", viewport_info.zoom_level.as_percentage()))
            .size(12)
            .style(Color::from_rgb(0.2, 0.6, 0.9));
            
        let zoom_in_button = button("🔍+")
            .padding(4)
            .on_press(Message::ZoomIn)
            .style(theme::Button::Secondary);
            
        let zoom_reset_button = button("🎯")
            .padding(4)
            .on_press(Message::ZoomReset)
            .style(theme::Button::Secondary);
        
        Row::new()
            .push(zoom_out_button)
            .push(container(zoom_level_text)
                .padding([4, 8])
                .center_x())
            .push(zoom_in_button)
            .push(Space::with_width(4))
            .push(zoom_reset_button)
            .spacing(2)
            .align_items(Alignment::Center)
            .into()
    }
    
    /// Create scrollable content with proper viewport handling
    fn create_scrollable_content<'a>(
        &'a self,
        content: Element<'a, Message>,
        viewport_info: &ViewportInfo,
        scroll_state: Option<&ScrollState>,
    ) -> Element<'a, Message> {
        // Create enhanced scrollable with zoom awareness
        let scrollable_view = scrollable(content)
            .height(Length::Fill)
            .width(Length::Fill)
            .direction(scrollable::Direction::Both {
                vertical: scrollable::Properties::new(),
                horizontal: scrollable::Properties::new(),
            });
        
        // Apply zoom transformation by adjusting scrollable properties
        if viewport_info.zoom_level != ZoomLevel::Percent100 {
            // Note: Iced doesn't directly support zoom transforms
            // This would need custom rendering or wrapper containers
            log::debug!("Zoom level {}: would apply zoom transform in full implementation", 
                       viewport_info.zoom_level.as_percentage());
        }
        
        // Create scroll indicator overlay if scroll state is available
        if let Some(scroll) = scroll_state {
            let scroll_indicators = self.create_scroll_indicators(scroll);
            
            // Layer the scrollable content with scroll indicators
            container(
                Column::new()
                    .push(scrollable_view)
                    .push(scroll_indicators)
                    .spacing(0)
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
        } else {
            scrollable_view.into()
        }
    }
    
    /// Create scroll position indicators
    fn create_scroll_indicators(&self, scroll_state: &ScrollState) -> Element<Message> {
        let scroll_info = if scroll_state.max_x > 0.0 || scroll_state.max_y > 0.0 {
            let h_percent = if scroll_state.max_x > 0.0 {
                (scroll_state.x / scroll_state.max_x * 100.0).round() as u16
            } else {
                0
            };
            
            let v_percent = if scroll_state.max_y > 0.0 {
                (scroll_state.y / scroll_state.max_y * 100.0).round() as u16
            } else {
                0
            };
            
            if scroll_state.max_x > 0.0 && scroll_state.max_y > 0.0 {
                format!("↕️ {}% ↔️ {}%", v_percent, h_percent)
            } else if scroll_state.max_y > 0.0 {
                format!("↕️ {}%", v_percent)
            } else {
                format!("↔️ {}%", h_percent)
            }
        } else {
            "No scroll".to_string()
        };
        
        container(
            text(scroll_info)
                .size(10)
                .style(Color::from_rgb(0.5, 0.5, 0.5))
        )
        .padding([2, 8])
        .style(theme::Container::Custom(Box::new(InfoBarStyle)))
        .width(Length::Shrink)
        .into()
    }
    
    /// Create keyboard navigation hints
    #[allow(dead_code)] // Will be used when implementing navigation hints
    fn create_navigation_hints(&self) -> Element<Message> {
        let hints_text = "⌨️ Ctrl+/- Zoom • ↑↓←→ Scroll • PgUp/PgDn • Home/End";
        
        container(
            text(hints_text)
                .size(10)
                .style(Color::from_rgb(0.4, 0.4, 0.4))
        )
        .padding([2, 8])
        .center_x()
        .width(Length::Fill)
        .into()
    }
    
    /// Create responsive viewport info display
    #[allow(dead_code)] // Will be used when implementing viewport info display
    fn create_viewport_info(&self, viewport_info: &ViewportInfo) -> Element<Message> {
        let viewport_text = format!(
            "📐 {}x{} @ {}% (DPR: {:.1})",
            viewport_info.width as u16,
            viewport_info.height as u16,
            viewport_info.zoom_level.as_percentage(),
            viewport_info.device_pixel_ratio
        );
        
        container(
            text(viewport_text)
                .size(10)
                .style(Color::from_rgb(0.5, 0.5, 0.5))
        )
        .padding([2, 8])
        .into()
    }

    // ── Privacy Scoreboard ────────────────────────────────────────────

    /// Render the privacy scoreboard side panel.
    ///
    /// Shows live counters for trackers blocked, fingerprints neutralized,
    /// local DNS queries, and other privacy actions.  An expandable section
    /// lists the most recent events.
    fn privacy_scoreboard_view(
        stats: &PrivacyStats,
        expanded: bool,
    ) -> Element<'static, Message> {
        // ── Header ──────────────────────────────────────────────────
        let total = stats.total_actions();
        let header = Row::new()
            .push(
                text("Privacy Shield")
                    .size(14)
                    .style(Color::from_rgb(0.0, 0.75, 0.55)),
            )
            .push(Space::with_width(Length::Fill))
            .push(
                text(format!("{}", total))
                    .size(14)
                    .style(Color::from_rgb(0.9, 0.9, 0.9)),
            )
            .align_items(Alignment::Center);

        // ── Stat rows ───────────────────────────────────────────────
        let stat_row = |label: &str, count: u64, color: Color| -> Element<'static, Message> {
            container(
                Row::new()
                    .push(text(label).size(12).style(Color::from_rgb(0.7, 0.7, 0.7)))
                    .push(Space::with_width(Length::Fill))
                    .push(text(format!("{}", count)).size(12).style(color))
                    .align_items(Alignment::Center)
                    .padding([4, 6]),
            )
            .style(theme::Container::Custom(Box::new(PrivacyStatRowStyle)))
            .width(Length::Fill)
            .into()
        };

        let trackers_row = stat_row(
            "Trackers Blocked",
            stats.trackers_blocked,
            Color::from_rgb(1.0, 0.35, 0.35),
        );
        let fingerprints_row = stat_row(
            "Fingerprints Neutralized",
            stats.fingerprints_neutralized,
            Color::from_rgb(0.95, 0.65, 0.1),
        );
        let dns_row = stat_row(
            "DNS Queries Local",
            stats.dns_queries_local,
            Color::from_rgb(0.2, 0.7, 0.95),
        );
        let api_row = stat_row(
            "APIs Blocked",
            stats.apis_not_implemented,
            Color::from_rgb(0.6, 0.5, 0.9),
        );
        let csp_row = stat_row(
            "CSP Violations",
            stats.csp_violations,
            Color::from_rgb(0.9, 0.4, 0.6),
        );

        let mut panel = Column::new()
            .push(header)
            .push(Space::with_height(8))
            .push(trackers_row)
            .push(Space::with_height(4))
            .push(fingerprints_row)
            .push(Space::with_height(4))
            .push(dns_row)
            .push(Space::with_height(4))
            .push(api_row)
            .push(Space::with_height(4))
            .push(csp_row)
            .spacing(0);

        // ── Dropped events warning ──────────────────────────────────
        if stats.events_dropped > 0 {
            panel = panel
                .push(Space::with_height(6))
                .push(
                    text(format!("Warning: {} events dropped", stats.events_dropped))
                        .size(10)
                        .style(Color::from_rgb(1.0, 0.6, 0.0)),
                );
        }

        // ── Toggle button for recent events ─────────────────────────
        let toggle_label = if expanded {
            "Hide Recent Events"
        } else {
            "Show Recent Events"
        };

        panel = panel
            .push(Space::with_height(8))
            .push(
                button(text(toggle_label).size(11))
                    .padding([4, 8])
                    .on_press(Message::TogglePrivacyPanel)
                    .style(theme::Button::Secondary),
            );

        // ── Recent events list ──────────────────────────────────────
        if expanded && !stats.recent_events.is_empty() {
            // Show the most recent 20 events in reverse order
            let visible_count = stats.recent_events.len().min(20);
            let start = stats.recent_events.len().saturating_sub(visible_count);

            let mut events_col = Column::new().spacing(2);
            for event in stats.recent_events[start..].iter().rev() {
                let (icon, summary, color) = Self::format_privacy_event(event);
                events_col = events_col.push(
                    container(
                        Row::new()
                            .push(text(icon).size(10))
                            .push(Space::with_width(4))
                            .push(text(summary).size(10).style(color))
                            .align_items(Alignment::Center),
                    )
                    .padding([2, 4])
                    .width(Length::Fill),
                );
            }

            panel = panel
                .push(Space::with_height(6))
                .push(
                    scrollable(events_col)
                        .height(Length::Fill),
                );
        }

        container(panel)
            .padding(10)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(theme::Container::Custom(Box::new(PrivacyPanelStyle)))
            .into()
    }

    /// Format a single privacy event into (icon, summary_text, color).
    fn format_privacy_event(event: &PrivacyEvent) -> (&'static str, String, Color) {
        match event {
            PrivacyEvent::TrackerBlocked { url, category, .. } => {
                // Truncate the URL to keep the panel tidy
                let short_url = if url.len() > 40 {
                    format!("{}...", &url[..37])
                } else {
                    url.clone()
                };
                (
                    "X",
                    format!("{} ({})", short_url, category),
                    Color::from_rgb(1.0, 0.35, 0.35),
                )
            }
            PrivacyEvent::FingerprintNeutralized { api_name, action_taken } => (
                "~",
                format!("{}: {}", api_name, action_taken),
                Color::from_rgb(0.95, 0.65, 0.1),
            ),
            PrivacyEvent::DnsQueryLocal { domain, cached } => {
                let cache_str = if *cached { "cached" } else { "resolved" };
                (
                    "D",
                    format!("{} ({})", domain, cache_str),
                    Color::from_rgb(0.2, 0.7, 0.95),
                )
            }
            PrivacyEvent::ApiNotImplemented { api_name, caller_origin } => {
                let short_origin = if caller_origin.len() > 25 {
                    format!("{}...", &caller_origin[..22])
                } else {
                    caller_origin.clone()
                };
                (
                    "!",
                    format!("{} from {}", api_name, short_origin),
                    Color::from_rgb(0.6, 0.5, 0.9),
                )
            }
            PrivacyEvent::CspViolation { directive, blocked_uri } => {
                let short_uri = if blocked_uri.len() > 30 {
                    format!("{}...", &blocked_uri[..27])
                } else {
                    blocked_uri.clone()
                };
                (
                    "C",
                    format!("{}: {}", directive, short_uri),
                    Color::from_rgb(0.9, 0.4, 0.6),
                )
            }
            PrivacyEvent::EventsDropped { count } => (
                "?",
                format!("{} dropped", count),
                Color::from_rgb(1.0, 0.6, 0.0),
            ),
        }
    }
}

impl Default for CitadelUI {
    fn default() -> Self {
        Self::new()
    }
}