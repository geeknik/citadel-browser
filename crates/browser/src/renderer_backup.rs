//! Temporary renderer backup module for Citadel Browser
//! This provides fallback rendering functionality

use iced::widget::{text, container, column};
use iced::{Element, Color, Length};
use crate::app::Message;
use crate::ui::UIMessage;

/// Simple backup renderer
pub struct BackupRenderer {
    enabled: bool,
}

impl BackupRenderer {
    pub fn new() -> Self {
        Self { enabled: true }
    }

    pub fn render(&self) -> Element<Message> {
        if !self.enabled {
            return text("Renderer disabled").into();
        }

        container(
            column![
                text("Citadel Browser - Backup Renderer")
                    .size(24)
                    .style(Color::from_rgb(0.2, 0.4, 0.8)),
                text("Advanced rendering features are temporarily unavailable")
                    .size(16)
                    .style(Color::from_rgb(0.5, 0.5, 0.5)),
            ]
            .spacing(10)
        )
        .padding(20)
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x()
        .center_y()
        .into()
    }
}

impl Default for BackupRenderer {
    fn default() -> Self {
        Self::new()
    }
}