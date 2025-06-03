use std::sync::Arc;
use iced::{
    widget::{button, column, container, row, text, text_input, scrollable, Space},
    Element, Length, Alignment, Color, Background,
};

use citadel_networking::{NetworkConfig, PrivacyLevel};
use crate::tabs::TabManager;
use crate::app::Message;

/// UI state and components for the Citadel Browser
pub struct CitadelUI {
    /// Current URL in the address bar
    address_bar_value: String,
    /// Whether the address bar is focused
    address_bar_focused: bool,
}

/// Messages specific to UI interactions
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
    /// Create a new UI instance
    pub fn new() -> Self {
        Self {
            address_bar_value: "https://citadelbrowser.com".to_string(),
            address_bar_focused: false,
        }
    }
    
    /// Update UI state based on messages
    pub fn update(&mut self, message: UIMessage) -> iced::Command<Message> {
        match message {
            UIMessage::AddressBarChanged(value) => {
                self.address_bar_value = value;
                iced::Command::none()
            }
            UIMessage::AddressBarSubmitted => {
                let url = self.address_bar_value.clone();
                iced::Command::perform(async move { url }, Message::Navigate)
            }
            UIMessage::AddressBarFocused => {
                self.address_bar_focused = true;
                iced::Command::none()
            }
            UIMessage::AddressBarUnfocused => {
                self.address_bar_focused = false;
                iced::Command::none()
            }
        }
    }
    
    /// Create the main UI view
    pub fn view(
        &self,
        tab_manager: &Arc<TabManager>,
        network_config: &NetworkConfig,
    ) -> Element<Message> {
        let content = column![
            self.create_toolbar(tab_manager, network_config),
            self.create_content_area(tab_manager),
        ]
        .spacing(0);
        
        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_theme| container::Appearance {
                background: Some(Background::Color(Color::from_rgb(0.1, 0.1, 0.1))),
                ..Default::default()
            })
            .into()
    }
    
    /// Create the browser toolbar
    fn create_toolbar(
        &self,
        tab_manager: &Arc<TabManager>,
        network_config: &NetworkConfig,
    ) -> Element<Message> {
        let navigation_buttons = row![
            button("←")
                .padding(8),
            button("→")
                .padding(8),
            button("⟳")
                .padding(8),
        ]
        .spacing(4);
        
        let address_bar = text_input("Enter URL...", &self.address_bar_value)
            .on_input(|value| Message::UI(UIMessage::AddressBarChanged(value)))
            .on_submit(Message::UI(UIMessage::AddressBarSubmitted))
            .padding(8)
            .width(Length::Fill);
        
        let privacy_indicator = self.create_privacy_indicator(network_config);
        
        let new_tab_button = button("+")
            .padding(8)
            .on_press(Message::NewTab);
        
        let toolbar = row![
            navigation_buttons,
            Space::with_width(8),
            address_bar,
            Space::with_width(8),
            privacy_indicator,
            Space::with_width(8),
            new_tab_button,
        ]
        .align_items(Alignment::Center)
        .padding(8);
        
        container(toolbar)
            .width(Length::Fill)
            .style(|_theme| container::Appearance {
                background: Some(Background::Color(Color::from_rgb(0.15, 0.15, 0.15))),
                border_color: Color::from_rgb(0.3, 0.3, 0.3),
                border_width: 1.0,
                ..Default::default()
            })
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
    fn create_content_area(&self, tab_manager: &Arc<TabManager>) -> Element<Message> {
        let tabs_bar = self.create_tabs_bar(tab_manager);
        let page_content = self.create_page_content(tab_manager);
        
        column![tabs_bar, page_content]
            .spacing(0)
            .into()
    }
    
    /// Create the tabs bar
    fn create_tabs_bar(&self, tab_manager: &Arc<TabManager>) -> Element<Message> {
        let tabs = tab_manager.all_tabs();
        let active_tab_id = tab_manager.active_tab().map(|tab| tab.id());
        
        let mut tab_buttons = row![].spacing(2);
        
        for tab in tabs {
            let is_active = active_tab_id == Some(tab.id());
            let tab_title = if tab.title().is_empty() {
                "New Tab".to_string()
            } else {
                tab.title()
            };
            
            let tab_button = button(
                row![
                    text(tab_title).width(Length::Fixed(150.0)),
                    button("×")
                        .padding(2)
                        .on_press(Message::CloseTab(tab.id()))
                ]
                .align_items(Alignment::Center)
            )
            .padding(8)
            .on_press(Message::SwitchTab(tab.id()));
            
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
        .style(|_theme| container::Appearance {
            background: Some(Background::Color(Color::from_rgb(0.12, 0.12, 0.12))),
            border_color: Color::from_rgb(0.3, 0.3, 0.3),
            border_width: 1.0,
            ..Default::default()
        })
        .into()
    }
    
    /// Create the page content area
    fn create_page_content(&self, tab_manager: &Arc<TabManager>) -> Element<Message> {
        if let Some(active_tab) = tab_manager.active_tab() {
            let content = if active_tab.is_loading() {
                column![
                    Space::with_height(100),
                    text("Loading...")
                        .size(24)
                        .style(Color::from_rgb(0.7, 0.7, 0.7)),
                    Space::with_height(20),
                    text(format!("Fetching: {}", active_tab.url()))
                        .size(14)
                        .style(Color::from_rgb(0.5, 0.5, 0.5)),
                ]
                .align_items(Alignment::Center)
            } else {
                // TODO: Render actual page content
                column![
                    Space::with_height(50),
                    text("Page Loaded Successfully")
                        .size(20)
                        .style(Color::from_rgb(0.0, 0.8, 0.0)),
                    Space::with_height(20),
                    text(format!("URL: {}", active_tab.url()))
                        .size(14)
                        .style(Color::from_rgb(0.7, 0.7, 0.7)),
                    Space::with_height(20),
                    text("Content rendering will be implemented in the next iteration")
                        .size(12)
                        .style(Color::from_rgb(0.5, 0.5, 0.5)),
                ]
                .align_items(Alignment::Center)
            };
            
            container(content)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x()
                .style(|_theme| container::Appearance {
                    background: Some(Background::Color(Color::from_rgb(0.08, 0.08, 0.08))),
                    ..Default::default()
                })
                .into()
        } else {
            container(
                column![
                    Space::with_height(50),
                    text(format!("Welcome to Citadel Browser v{}", env!("CARGO_PKG_VERSION")))
                        .size(32)
                        .style(Color::from_rgb(0.8, 0.8, 0.8)),
                    Space::with_height(10),
                    text("Privacy-First Web Browser")
                        .size(16)
                        .style(Color::from_rgb(0.6, 0.6, 0.6)),
                    Space::with_height(20),
                    text("⚠️ ALPHA SOFTWARE - USE AT YOUR OWN RISK ⚠️")
                        .size(14)
                        .style(Color::from_rgb(1.0, 0.6, 0.0)),
                    Space::with_height(10),
                    text("This is experimental software not intended for production use")
                        .size(12)
                        .style(Color::from_rgb(0.8, 0.4, 0.4)),
                    Space::with_height(30),
                    button("Create New Tab")
                        .padding(12)
                        .on_press(Message::NewTab),
                ]
                .align_items(Alignment::Center)
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .style(|_theme| container::Appearance {
                background: Some(Background::Color(Color::from_rgb(0.08, 0.08, 0.08))),
                ..Default::default()
            })
            .into()
        }
    }
}

impl Default for CitadelUI {
    fn default() -> Self {
        Self::new()
    }
}