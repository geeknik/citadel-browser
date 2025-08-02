use std::sync::Arc;
use iced::{
    widget::{button, container, text, text_input, scrollable, Space, Column, Row},
    Element, Length, Color, Alignment, theme, Background,
    widget::container::{Appearance, StyleSheet},
};
use citadel_tabs::{SendSafeTabManager as TabManager};
use crate::app::Message;
use crate::renderer::CitadelRenderer;
use citadel_networking::{NetworkConfig, PrivacyLevel};

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
    AddressBarFocused,
    /// Address bar unfocused
    AddressBarUnfocused,
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
        }
        iced::Command::none()
    }

    /// Create the main UI view
    pub fn view<'a>(
        &'a self,
        tab_manager: &Arc<TabManager>,
        network_config: &NetworkConfig,
        renderer: &'a CitadelRenderer,
    ) -> Element<'a, Message> {
        let content = Column::new()
            .push(self.create_toolbar(tab_manager, network_config))
            .push(self.create_content_area(tab_manager, renderer))
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
    fn create_content_area<'a>(&'a self, tab_manager: &Arc<TabManager>, renderer: &'a CitadelRenderer) -> Element<'a, Message> {
        let tabs_bar = self.create_tabs_bar(tab_manager);
        let page_content = self.create_page_content(tab_manager, renderer);
        
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
    fn create_page_content<'a>(&'a self, tab_manager: &Arc<TabManager>, renderer: &'a CitadelRenderer) -> Element<'a, Message> {
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
                    url, 
                    title, 
                    content: _, 
                    element_count, 
                    size_bytes 
                } => {
                    // Get the actual rendered content from the renderer
                    let rendered_content = renderer.render();
                    
                    // Create a minimal header with essential info
                    let header = Row::new()
                        .push(text(format!("📊 {} elements", element_count))
                            .size(11)
                            .style(Color::from_rgb(0.6, 0.6, 0.6)))
                        .push(text(" • ").size(11).style(Color::from_rgb(0.5, 0.5, 0.5)))
                        .push(text(format!("{} bytes", size_bytes))
                            .size(11)
                            .style(Color::from_rgb(0.6, 0.6, 0.6)))
                        .push(text(" • ").size(11).style(Color::from_rgb(0.5, 0.5, 0.5)))
                        .push(text("🛡️ ZKVM Active")
                            .size(11)
                            .style(Color::from_rgb(0.0, 0.6, 0.8)))
                        .spacing(0)
                        .align_items(Alignment::Center);
                    
                    // Prioritize the rendered content - put it first with minimal header
                    let full_content = Column::new()
                        .push(container(header)
                            .width(Length::Fill)
                            .padding([5, 10, 5, 10])
                            .style(theme::Container::Custom(Box::new(InfoBarStyle))))
                        .push(rendered_content)
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
}

impl Default for CitadelUI {
    fn default() -> Self {
        Self::new()
    }
}