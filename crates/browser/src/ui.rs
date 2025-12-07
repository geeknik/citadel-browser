use std::sync::Arc;
use iced::{
    widget::{button, container, text, text_input, scrollable, Space, Column, Row, horizontal_rule},
    Element, Length, Color, Alignment, theme, Background,
    widget::container::{Appearance, StyleSheet},
};
use citadel_tabs::{SendSafeTabManager as TabManager};
use crate::app::{Message, ViewportInfo, ScrollState, ZoomLevel};
use crate::renderer::CitadelRenderer;
use citadel_networking::{NetworkConfig, PrivacyLevel};
use crate::history::{NavigationManager, TransitionType};
use crate::bookmarks::{BookmarkManager, Bookmark};
use crate::settings::{BrowserSettings, AppTheme};
use crate::downloads::{DownloadManager, DownloadItem};

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
    /// Navigation button states
    navigation_state: NavigationState,
    /// Current UI theme
    current_theme: AppTheme,
    /// Active downloads count
    active_downloads_count: usize,
    /// Bookmark suggestions for address bar
    bookmark_suggestions: Vec<String>,
    /// History suggestions for address bar
    history_suggestions: Vec<String>,
    /// UI layout state
    layout_state: UILayoutState,
}

/// Navigation button states
#[derive(Debug, Clone)]
pub struct NavigationState {
    /// Can go back
    pub can_go_back: bool,
    /// Can go forward
    pub can_go_forward: bool,
    /// Can refresh
    pub can_refresh: bool,
    /// Can stop loading
    pub can_stop: bool,
    /// Current page is loading
    pub is_loading: bool,
}

/// UI layout state
#[derive(Debug, Clone)]
pub struct UILayoutState {
    /// Show bookmarks bar
    pub show_bookmarks_bar: bool,
    /// Show downloads bar
    pub show_downloads_bar: bool,
    /// Show tab bar
    pub show_tab_bar: bool,
    /// Show navigation bar
    pub show_nav_bar: bool,
    /// Show sidebar
    pub show_sidebar: bool,
    /// Sidebar width
    pub sidebar_width: f32,
}

impl Default for NavigationState {
    fn default() -> Self {
        Self {
            can_go_back: false,
            can_go_forward: false,
            can_refresh: true,
            can_stop: false,
            is_loading: false,
        }
    }
}

impl Default for UILayoutState {
    fn default() -> Self {
        Self {
            show_bookmarks_bar: true,
            show_downloads_bar: false,
            show_tab_bar: true,
            show_nav_bar: true,
            show_sidebar: false,
            sidebar_width: 300.0,
        }
    }
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
    /// Zoom level changed from UI
    ZoomChanged(ZoomLevel),
    /// Scroll position changed from UI
    ScrollChanged { x: f32, y: f32 },
    /// Navigation button clicked
    NavigateBack,
    NavigateForward,
    NavigateRefresh,
    NavigateStop,
    NavigateHome,
    /// Bookmark button clicked
    BookmarkCurrent,
    /// Settings button clicked
    OpenSettings,
    /// Downloads button clicked
    ToggleDownloads,
    /// History button clicked
    OpenHistory,
    /// Sidebar toggle
    ToggleSidebar,
    /// Layout state changed
    LayoutChanged(UILayoutState),
    /// Theme changed
    ThemeChanged(AppTheme),
}

impl CitadelUI {
    /// Create a new UI state
    pub fn new() -> Self {
        Self {
            address_bar_value: String::new(),
            address_bar_focused: false,
            navigation_state: NavigationState::default(),
            current_theme: AppTheme::Dark,
            active_downloads_count: 0,
            bookmark_suggestions: Vec::new(),
            history_suggestions: Vec::new(),
            layout_state: UILayoutState::default(),
        }
    }

    /// Get the current address bar value
    pub fn address_bar_value(&self) -> &str {
        &self.address_bar_value
    }

    /// Update navigation state
    pub fn update_navigation_state(&mut self, can_go_back: bool, can_go_forward: bool, is_loading: bool) {
        self.navigation_state.can_go_back = can_go_back;
        self.navigation_state.can_go_forward = can_go_forward;
        self.navigation_state.is_loading = is_loading;
        self.navigation_state.can_stop = is_loading;
        self.navigation_state.can_refresh = !is_loading;
    }

    /// Update address bar value
    pub fn update_address_bar(&mut self, url: String) {
        self.address_bar_value = url;
    }

    /// Update active downloads count
    pub fn update_downloads_count(&mut self, count: usize) {
        self.active_downloads_count = count;
        // Auto-show downloads bar when there are active downloads
        self.layout_state.show_downloads_bar = count > 0;
    }

    /// Update bookmark suggestions
    pub fn update_bookmark_suggestions(&mut self, suggestions: Vec<String>) {
        self.bookmark_suggestions = suggestions;
    }

    /// Update history suggestions
    pub fn update_history_suggestions(&mut self, suggestions: Vec<String>) {
        self.history_suggestions = suggestions;
    }

    /// Apply settings
    pub fn apply_settings(&mut self, settings: &BrowserSettings) {
        self.current_theme = settings.ui.theme.clone();
        self.layout_state.show_bookmarks_bar = settings.ui.show_bookmarks_bar;
        self.layout_state.show_downloads_bar = settings.ui.show_downloads_bar;
        self.layout_state.show_tab_bar = settings.ui.show_tab_bar;
        self.layout_state.show_nav_bar = settings.ui.show_nav_bar;
    }

    /// Update the UI state based on messages
    pub fn update(&mut self, message: UIMessage) -> iced::Command<Message> {
        match message {
            UIMessage::AddressBarChanged(value) => {
                self.address_bar_value = value;
            }
            UIMessage::AddressBarSubmitted => {
                if !self.address_bar_value.trim().is_empty() {
                    let url = self.address_bar_value.clone();
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
            UIMessage::NavigateBack => {
                return iced::Command::perform(
                    async {},
                    |_| Message::Back,
                );
            }
            UIMessage::NavigateForward => {
                return iced::Command::perform(
                    async {},
                    |_| Message::Forward,
                );
            }
            UIMessage::NavigateRefresh => {
                return iced::Command::perform(
                    async {},
                    |_| Message::RefreshTab,
                );
            }
            UIMessage::NavigateStop => {
                // TODO: Implement stop loading
                log::info!("Stop loading requested");
            }
            UIMessage::NavigateHome => {
                return iced::Command::perform(
                    async {},
                    |_| Message::Navigate("about:home".to_string()),
                );
            }
            UIMessage::BookmarkCurrent => {
                // TODO: Implement bookmark current page
                log::info!("Bookmark current page requested");
            }
            UIMessage::OpenSettings => {
                // TODO: Implement settings dialog
                log::info!("Open settings requested");
            }
            UIMessage::ToggleDownloads => {
                self.layout_state.show_downloads_bar = !self.layout_state.show_downloads_bar;
            }
            UIMessage::OpenHistory => {
                // TODO: Implement history sidebar
                log::info!("Open history requested");
            }
            UIMessage::ToggleSidebar => {
                self.layout_state.show_sidebar = !self.layout_state.show_sidebar;
            }
            UIMessage::ThemeChanged(theme) => {
                self.current_theme = theme;
            }
            UIMessage::LayoutChanged(layout) => {
                self.layout_state = layout;
            }
            UIMessage::ZoomChanged(_zoom_level) => {
                // Zoom changes are handled at the app level
            }
            UIMessage::ScrollChanged { x: _, y: _ } => {
                // Scroll changes are handled at the app level
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
    ) -> Element<'a, Message> {
        let mut content = Column::new();

        // Add navigation bar
        if self.layout_state.show_nav_bar {
            content = content.push(self.create_toolbar(tab_manager, network_config, viewport_info));
        }

        // Add bookmarks bar
        if self.layout_state.show_bookmarks_bar {
            content = content.push(self.create_bookmarks_bar());
        }

        // Add tabs bar
        if self.layout_state.show_tab_bar {
            content = content.push(self.create_tabs_bar(tab_manager));
        }

        // Add main content area with sidebar
        let main_content = self.create_main_content_area(tab_manager, renderer, viewport_info, scroll_state);

        if self.layout_state.show_sidebar {
            let sidebar_content = self.create_sidebar();
            content = content.push(
                Row::new()
                    .push(sidebar_content)
                    .push(main_content)
            );
        } else {
            content = content.push(main_content);
        }

        // Add downloads bar
        if self.layout_state.show_downloads_bar {
            content = content.push(self.create_downloads_bar());
        }

        content = content.spacing(0);

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
        let navigation_buttons = self.create_navigation_buttons();
        let address_bar = self.create_address_bar();
        let privacy_indicator = self.create_privacy_indicator(network_config);
        let zoom_controls = self.create_zoom_controls(viewport_info);
        let action_buttons = self.create_action_buttons();

        let toolbar = Row::new()
            .push(navigation_buttons)
            .push(Space::with_width(8))
            .push(address_bar)
            .push(Space::with_width(8))
            .push(zoom_controls)
            .push(Space::with_width(8))
            .push(privacy_indicator)
            .push(Space::with_width(8))
            .push(action_buttons)
            .align_items(Alignment::Center)
            .padding(8);

        container(toolbar)
            .width(Length::Fill)
            .style(theme::Container::Custom(Box::new(InfoBarStyle)))
            .into()
    }

    /// Create navigation buttons
    fn create_navigation_buttons(&self) -> Element<Message> {
        let back_button = button(text("←").size(16))
            .padding(8)
            .style(if self.navigation_state.can_go_back {
                theme::Button::Primary
            } else {
                theme::Button::Secondary
            })
            .on_press_maybe(if self.navigation_state.can_go_back {
                Some(Message::UI(UIMessage::NavigateBack))
            } else {
                None
            });

        let forward_button = button(text("→").size(16))
            .padding(8)
            .style(if self.navigation_state.can_go_forward {
                theme::Button::Primary
            } else {
                theme::Button::Secondary
            })
            .on_press_maybe(if self.navigation_state.can_go_forward {
                Some(Message::UI(UIMessage::NavigateForward))
            } else {
                None
            });

        let refresh_or_stop = if self.navigation_state.is_loading {
            button(text("⏹").size(16))
                .padding(8)
                .style(theme::Button::Destructive)
                .on_press(Message::UI(UIMessage::NavigateStop))
        } else {
            button(text("⟳").size(16))
                .padding(8)
                .style(if self.navigation_state.can_refresh {
                    theme::Button::Secondary
                } else {
                    theme::Button::Primary
                })
                .on_press_maybe(if self.navigation_state.can_refresh {
                    Some(Message::UI(UIMessage::NavigateRefresh))
                } else {
                    None
                })
        };

        let home_button = button(text("🏠").size(16))
            .padding(8)
            .style(theme::Button::Secondary)
            .on_press(Message::UI(UIMessage::NavigateHome));

        Row::new()
            .push(back_button)
            .push(forward_button)
            .push(refresh_or_stop)
            .push(home_button)
            .spacing(2)
            .into()
    }

    /// Create address bar
    fn create_address_bar(&self) -> Element<Message> {
        let address_input = text_input("Enter URL or search...", &self.address_bar_value)
            .on_input(|value| Message::UI(UIMessage::AddressBarChanged(value)))
            .on_submit(Message::UI(UIMessage::AddressBarSubmitted))
            .padding(10);

        container(address_input)
            .width(Length::Fill)
            .into()
    }

    /// Create action buttons (new tab, bookmarks, settings, etc.)
    fn create_action_buttons(&self) -> Element<Message> {
        let new_tab_button = button(text("+").size(16))
            .padding(8)
            .style(theme::Button::Primary)
            .on_press(Message::NewTab {
                tab_type: citadel_tabs::TabType::Ephemeral,
                initial_url: None
            });

        let bookmark_button = button(text("⭐").size(16))
            .padding(8)
            .style(theme::Button::Secondary)
            .on_press(Message::UI(UIMessage::BookmarkCurrent));

        let downloads_button = {
            let button_style = if self.active_downloads_count > 0 {
                theme::Button::Primary
            } else {
                theme::Button::Secondary
            };

            let button_text = if self.active_downloads_count > 0 {
                format!("📥 ({})", self.active_downloads_count)
            } else {
                "📥".to_string()
            };

            button(text(button_text).size(14))
                .padding(8)
                .style(button_style)
                .on_press(Message::UI(UIMessage::ToggleDownloads))
        };

        let settings_button = button(text("⚙️").size(16))
            .padding(8)
            .style(theme::Button::Secondary)
            .on_press(Message::UI(UIMessage::OpenSettings));

        let history_button = button(text("📚").size(16))
            .padding(8)
            .style(theme::Button::Secondary)
            .on_press(Message::UI(UIMessage::OpenHistory));

        Row::new()
            .push(new_tab_button)
            .push(Space::with_width(4))
            .push(bookmark_button)
            .push(Space::with_width(4))
            .push(downloads_button)
            .push(Space::with_width(4))
            .push(history_button)
            .push(Space::with_width(4))
            .push(settings_button)
            .spacing(2)
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

        button(text(indicator_text).size(12).style(indicator_color))
            .padding(6)
            .style(theme::Button::Text)
            .into()
    }

    /// Create the zoom controls for the toolbar
    fn create_zoom_controls(&self, viewport_info: &ViewportInfo) -> Element<Message> {
        let zoom_out_button = button(text("−").size(16))
            .padding(4)
            .on_press(Message::ZoomOut)
            .style(theme::Button::Secondary);

        let zoom_level_text = text(format!("{}%", viewport_info.zoom_level.as_percentage()))
            .size(12)
            .style(Color::from_rgb(0.2, 0.6, 0.9));

        let zoom_in_button = button(text("+").size(16))
            .padding(4)
            .on_press(Message::ZoomIn)
            .style(theme::Button::Secondary);

        let zoom_reset_button = button(text("🎯").size(16))
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

    /// Create bookmarks bar
    fn create_bookmarks_bar(&self) -> Element<Message> {
        // TODO: Load actual bookmarks from BookmarkManager
        let placeholder_bookmarks = vec![
            ("🔍 DuckDuckGo", "https://duckduckgo.com"),
            ("📰 News", "https://news.ycombinator.com"),
            ("🔧 GitHub", "https://github.com"),
        ];

        let mut bookmark_buttons = Row::new().spacing(4);

        for (title, url) in placeholder_bookmarks {
            let bookmark_button = button(text(title).size(12))
                .padding([4, 8])
                .style(theme::Button::Text)
                .on_press(Message::Navigate(url.to_string()));
            bookmark_buttons = bookmark_buttons.push(bookmark_button);
        }

        container(
            scrollable(bookmark_buttons)
                .direction(scrollable::Direction::Horizontal(
                    scrollable::Properties::default()
                ))
        )
        .width(Length::Fill)
        .padding([4, 8])
        .style(theme::Container::Custom(Box::new(InfoBarStyle)))
        .into()
    }

    /// Create downloads bar
    fn create_downloads_bar(&self) -> Element<Message> {
        let content = if self.active_downloads_count > 0 {
            text(format!("📥 {} active download(s)", self.active_downloads_count))
                .size(12)
                .style(Color::from_rgb(0.0, 0.6, 0.8))
        } else {
            text("📥 No active downloads")
                .size(12)
                .style(Color::from_rgb(0.6, 0.6, 0.6))
        };

        container(
            Row::new()
                .push(content)
                .push(Space::with_width(Length::Fill))
                .push(button(text("Hide").size(10))
                    .style(theme::Button::Text)
                    .on_press(Message::UI(UIMessage::ToggleDownloads)))
        )
        .padding([4, 8])
        .style(theme::Container::Custom(Box::new(InfoBarStyle)))
        .width(Length::Fill)
        .into()
    }

    /// Create sidebar
    fn create_sidebar(&self) -> Element<Message> {
        let sidebar_content = Column::new()
            .push(text("🔗 History")
                .size(14)
                .style(Color::from_rgb(0.8, 0.8, 0.8)))
            .push(Space::with_height(10))
            .push(text("⭐ Bookmarks")
                .size(14)
                .style(Color::from_rgb(0.8, 0.8, 0.8)))
            .push(Space::with_height(10))
            .push(text("📥 Downloads")
                .size(14)
                .style(Color::from_rgb(0.8, 0.8, 0.8)))
            .spacing(0);

        container(sidebar_content)
            .width(Length::Fixed(self.layout_state.sidebar_width))
            .height(Length::Fill)
            .style(theme::Container::Custom(Box::new(InfoBarStyle)))
            .into()
    }

    /// Create the main content area
    fn create_main_content_area<'a>(
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

            // Highlight active tab
            let button_style = if tab_state.is_active {
                theme::Button::Primary
            } else {
                theme::Button::Secondary
            };

            let tab_button = button(
                Row::new()
                    .push(text(tab_title).width(Length::Fixed(150.0)).size(12))
                    .push(Space::with_width(4))
                    .push(button(text("×").size(12))
                        .padding(2)
                        .style(theme::Button::Destructive)
                        .on_press(Message::CloseTab(tab_state.id)))
                    .align_items(Alignment::Center)
            )
            .padding([6, 8])
            .style(button_style)
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
                    url,
                    title: _,
                    content: _,
                    element_count,
                    size_bytes
                } => {
                    // Get the actual rendered content from the renderer
                    let rendered_content = renderer.render();

                    // Create a comprehensive header with scroll info and zoom level
                    let mut header_elements = Row::new()
                        .push(text(format!("🔗 {}", url))
                            .size(11)
                            .style(Color::from_rgb(0.6, 0.6, 0.8)))
                        .push(text(" • ").size(11).style(Color::from_rgb(0.5, 0.5, 0.5)))
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

    /// Create scrollable content with proper viewport handling
    fn create_scrollable_content<'a>(
        &'a self,
        content: Element<'a, Message>,
        viewport_info: &ViewportInfo,
        _scroll_state: Option<&ScrollState>,
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

        scrollable_view.into()
    }
}

impl Default for CitadelUI {
    fn default() -> Self {
        Self::new()
    }
}