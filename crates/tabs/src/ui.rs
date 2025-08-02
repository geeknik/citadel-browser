use iced::{
    widget::{button, container, text, Column, Row},
    Element, Padding,
};
use uuid::Uuid;
use crate::{TabState, TabType, SendSafeTabManager as TabManager};

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Uuid),
    TabClosed(Uuid),
    ConvertToContainerRequested(Uuid),
    ConvertToContainerConfirmed(Uuid),
    ConvertToContainerCancelled,
}

pub struct TabBar {
    manager: TabManager,
    show_conversion_dialog: Option<Uuid>,
}

impl TabBar {
    pub fn new(manager: TabManager) -> Self {
        Self {
            manager,
            show_conversion_dialog: None,
        }
    }
    
    pub fn update(&mut self, message: Message) {
        match message {
            Message::TabSelected(id) => {
                // For UI operations, we spawn async tasks
                let manager = self.manager.clone();
                tokio::spawn(async move {
                    let _ = manager.switch_tab(id).await;
                });
            }
            Message::TabClosed(id) => {
                let manager = self.manager.clone();
                tokio::spawn(async move {
                    let _ = manager.close_tab(id).await;
                });
            }
            Message::ConvertToContainerRequested(id) => {
                self.show_conversion_dialog = Some(id);
            }
            Message::ConvertToContainerConfirmed(id) => {
                let manager = self.manager.clone();
                tokio::spawn(async move {
                    let _ = manager.convert_to_container(id).await;
                });
                self.show_conversion_dialog = None;
            }
            Message::ConvertToContainerCancelled => {
                self.show_conversion_dialog = None;
            }
        }
    }
    
    pub fn view(&self) -> Element<Message> {
        let tabs = self.manager.get_tab_states();
        
        let tab_row = Row::new()
            .spacing(1)
            .padding(Padding::new(5.0))
            .push(
                tabs.iter()
                    .fold(Row::new(), |row, tab| {
                        row.push(self.tab_view(tab))
                    })
            );
        
        let mut content = Column::new().push(tab_row);
        
        // Add conversion dialog if needed
        if let Some(tab_id) = self.show_conversion_dialog {
            content = content.push(self.conversion_dialog_view(tab_id));
        }
        
        container(content).into()
    }
    
    fn tab_view(&self, tab: &TabState) -> Element<Message> {
        let title = text(&tab.title)
            .size(14);
            
        let close_button = button("×")
            .on_press(Message::TabClosed(tab.id))
            .padding(5);
            
        let mut tab_content = Row::new()
            .spacing(10)
            .padding(Padding::new(10.0))
            .push(title)
            .push(close_button);
            
        // Add convert button for ephemeral tabs
        if matches!(tab.tab_type, TabType::Ephemeral) {
            let convert_button = button("🔒")
                .on_press(Message::ConvertToContainerRequested(tab.id))
                .padding(5);
            tab_content = tab_content.push(convert_button);
        }
        
        // Wrap tab content in a container
        let tab_container = container(tab_content)
            .style(if tab.is_active {
                iced::theme::Container::Box
            } else {
                iced::theme::Container::Transparent
            });
            
        // Add a clickable button over the container for tab selection
        button(tab_container)
            .on_press(Message::TabSelected(tab.id))
            .style(iced::theme::Button::Text)
            .into()
    }
    
    fn conversion_dialog_view(&self, tab_id: Uuid) -> Element<Message> {
        let title = text("Convert to Container Tab?")
            .size(20);
            
        let description = text(
            "Converting this tab to a container will:\n\
            ✓ Allow state persistence between sessions\n\
            ✓ Enable bookmarks and history\n\
            ! Data will be stored on disk (encrypted)\n\
            ! Slightly increased attack surface\n\
            ! Must trust disk encryption"
        ).size(14);
        
        let buttons = Row::new()
            .spacing(20)
            .push(
                button("Keep Ephemeral")
                    .on_press(Message::ConvertToContainerCancelled)
                    .padding(10)
            )
            .push(
                button("Convert to Container")
                    .on_press(Message::ConvertToContainerConfirmed(tab_id))
                    .padding(10)
            );
            
        container(
            Column::new()
                .spacing(20)
                .padding(Padding::new(20.0))
                .push(title)
                .push(description)
                .push(buttons)
        )
        .style(iced::theme::Container::Box)
        .into()
    }
}

mod theme {
    use iced::widget::container;
    use iced::{Background, Color};
    
    pub enum Container {
        Default,
        Primary,
        Box,
    }
    
    impl container::StyleSheet for Container {
        type Style = iced::Theme;
        
        fn appearance(&self, _theme: &Self::Style) -> container::Appearance {
            match self {
                Container::Default => container::Appearance {
                    background: Some(Background::Color(Color::from_rgb(0.9, 0.9, 0.9))),
                    border: iced::Border {
                        color: Color::from_rgb(0.8, 0.8, 0.8),
                        width: 1.0,
                        radius: iced::border::Radius::from(5.0),
                    },
                    ..Default::default()
                },
                Container::Primary => container::Appearance {
                    background: Some(Background::Color(Color::from_rgb(0.8, 0.8, 1.0))),
                    border: iced::Border {
                        color: Color::from_rgb(0.7, 0.7, 0.9),
                        width: 1.0,
                        radius: iced::border::Radius::from(5.0),
                    },
                    ..Default::default()
                },
                Container::Box => container::Appearance {
                    background: Some(Background::Color(Color::from_rgb(1.0, 1.0, 1.0))),
                    border: iced::Border {
                        color: Color::from_rgb(0.8, 0.8, 0.8),
                        width: 2.0,
                        radius: iced::border::Radius::from(10.0),
                    },
                    ..Default::default()
                },
            }
        }
    }
} 