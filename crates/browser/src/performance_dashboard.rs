//! Performance monitoring dashboard for Citadel Browser
//!
//! This module provides a comprehensive performance monitoring dashboard
//! that visualizes real-time performance metrics and provides insights
//! for optimization and troubleshooting.

use std::sync::{Arc, RwLock, Mutex};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use log::info;
use iced::{
    widget::{container, column, row, text, scrollable, Space, button, progress_bar, Text, Column},
    Element, Length, Color, Theme, Alignment, Border,
};

use super::performance_integrator::{PerformanceIntegrator, PerformanceReport, PerformanceIssue};
use super::performance_benchmark::{PerformanceBenchmark, BenchmarkReport};
use super::memory_manager::MemoryStats;
use super::render_optimizer::FrameStats;

/// Performance dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Update interval for real-time metrics
    pub update_interval: Duration,
    /// History length for charts (number of data points)
    pub chart_history_length: usize,
    /// Enable advanced metrics
    pub enable_advanced_metrics: bool,
    /// Enable performance alerts
    pub enable_alerts: bool,
    /// Alert thresholds
    pub alert_thresholds: AlertThresholds,
}

/// Performance alert thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// FPS threshold for alerts
    pub fps_threshold: f32,
    /// Memory usage threshold (MB)
    pub memory_threshold_mb: f64,
    /// Page load time threshold (ms)
    pub load_time_threshold_ms: u64,
    /// Network error rate threshold (percentage)
    pub error_rate_threshold: f64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            fps_threshold: 30.0,
            memory_threshold_mb: 500.0,
            load_time_threshold_ms: 3000,
            error_rate_threshold: 5.0,
        }
    }
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            update_interval: Duration::from_millis(500), // 2Hz updates
            chart_history_length: 60, // 30 seconds of data at 2Hz
            enable_advanced_metrics: true,
            enable_alerts: true,
            alert_thresholds: AlertThresholds::default(),
        }
    }
}

/// Real-time performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeMetrics {
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    pub fps: f32,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub network_requests_per_second: f64,
    pub active_tabs: usize,
    pub render_time_ms: f64,
    pub layout_time_ms: f64,
    pub javascript_time_ms: f64,
    pub cache_hit_ratio: f64,
    pub scroll_performance: ScrollMetrics,
}

/// Scroll performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrollMetrics {
    pub average_scroll_speed: f32,
    pub dropped_frames_per_second: f32,
    pub input_latency_ms: f64,
    pub smoothness_score: f32,
}

impl Default for ScrollMetrics {
    fn default() -> Self {
        Self {
            average_scroll_speed: 0.0,
            dropped_frames_per_second: 0.0,
            input_latency_ms: 0.0,
            smoothness_score: 100.0,
        }
    }
}

/// Performance alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAlert {
    pub id: String,
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    pub severity: AlertSeverity,
    pub category: AlertCategory,
    pub title: String,
    pub description: String,
    pub current_value: f64,
    pub threshold: f64,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCategory {
    Performance,
    Memory,
    Network,
    Rendering,
    UserExperience,
}

/// Performance dashboard
pub struct PerformanceDashboard {
    config: DashboardConfig,
    performance_integrator: Arc<PerformanceIntegrator>,

    // Real-time metrics
    current_metrics: Arc<RwLock<RealTimeMetrics>>,
    metrics_history: Arc<RwLock<VecDeque<RealTimeMetrics>>>,

    // Performance issues and alerts
    current_issues: Arc<RwLock<Vec<PerformanceIssue>>>,
    active_alerts: Arc<RwLock<Vec<PerformanceAlert>>>,

    // Recent reports
    recent_reports: Arc<RwLock<Vec<PerformanceReport>>>,
    recent_benchmarks: Arc<RwLock<Vec<BenchmarkReport>>>,

    // UI state
    selected_tab: Arc<Mutex<DashboardTab>>,
    show_advanced: Arc<Mutex<bool>>,
    auto_refresh: Arc<Mutex<bool>>,

    // Last update time
    last_update: Arc<Mutex<Instant>>,
}

/// Dashboard tabs
#[derive(Debug, Clone, PartialEq)]
pub enum DashboardTab {
    Overview,
    Memory,
    Rendering,
    Network,
    Benchmarks,
    Alerts,
    Settings,
}

/// Dashboard message for UI updates
#[derive(Debug, Clone)]
pub enum DashboardMessage {
    UpdateMetrics,
    RefreshData,
    SelectTab(DashboardTab),
    ToggleAdvanced,
    ToggleAutoRefresh,
    RunBenchmark,
    AcknowledgeAlert(String),
    ClearAlerts,
    ExportReport,
}

impl PerformanceDashboard {
    /// Create a new performance dashboard
    pub fn new(performance_integrator: Arc<PerformanceIntegrator>) -> Self {
        Self::with_config(DashboardConfig::default(), performance_integrator)
    }

    /// Create a new performance dashboard with custom configuration
    pub fn with_config(config: DashboardConfig, performance_integrator: Arc<PerformanceIntegrator>) -> Self {
        Self {
            config,
            performance_integrator,
            current_metrics: Arc::new(RwLock::new(RealTimeMetrics {
                timestamp: Instant::now(),
                fps: 60.0,
                memory_usage_mb: 0.0,
                cpu_usage_percent: 0.0,
                network_requests_per_second: 0.0,
                active_tabs: 0,
                render_time_ms: 0.0,
                layout_time_ms: 0.0,
                javascript_time_ms: 0.0,
                cache_hit_ratio: 0.0,
                scroll_performance: ScrollMetrics::default(),
            })),
            metrics_history: Arc::new(RwLock::new(VecDeque::new())),
            current_issues: Arc::new(RwLock::new(Vec::new())),
            active_alerts: Arc::new(RwLock::new(Vec::new())),
            recent_reports: Arc::new(RwLock::new(Vec::new())),
            recent_benchmarks: Arc::new(RwLock::new(Vec::new())),
            selected_tab: Arc::new(Mutex::new(DashboardTab::Overview)),
            show_advanced: Arc::new(Mutex::new(false)),
            auto_refresh: Arc::new(Mutex::new(true)),
            last_update: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Update dashboard metrics
    pub async fn update_metrics(&self) {
        let now = Instant::now();

        // Update current metrics
        let metrics = self.collect_current_metrics().await;

        // Update history
        {
            let mut history = self.metrics_history.write().unwrap();
            history.push_back(metrics.clone());

            // Limit history length
            while history.len() > self.config.chart_history_length {
                history.pop_front();
            }
        }

        // Check for alerts
        if self.config.enable_alerts {
            self.check_for_alerts(&metrics).await;
        }

        // Update current metrics
        {
            let mut current = self.current_metrics.write().unwrap();
            *current = metrics;
        }

        // Update last update time
        {
            let mut last_update = self.last_update.lock().unwrap();
            *last_update = now;
        }
    }

    /// Get current dashboard view
    pub fn view(&self) -> Element<DashboardMessage> {
        let selected_tab = self.selected_tab.lock().unwrap().clone();
        let show_advanced = *self.show_advanced.lock().unwrap();
        let auto_refresh = *self.auto_refresh.lock().unwrap();

        let content = match selected_tab {
            DashboardTab::Overview => self.overview_view(),
            DashboardTab::Memory => self.memory_view(),
            DashboardTab::Rendering => self.rendering_view(),
            DashboardTab::Network => self.network_view(),
            DashboardTab::Benchmarks => self.benchmarks_view(),
            DashboardTab::Alerts => self.alerts_view(),
            DashboardTab::Settings => self.settings_view(),
        };

        let header = self.header_view(selected_tab, show_advanced, auto_refresh);

        container(column![
            header,
            Space::with_height(Length::Fixed(20.0)),
            content,
        ])
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(20)
        .into()
    }

    /// Handle dashboard message
    pub fn update(&mut self, message: DashboardMessage) {
        match message {
            DashboardMessage::UpdateMetrics => {
                // This would typically be handled by background task
            }
            DashboardMessage::RefreshData => {
                let dashboard = self.clone();
                tokio::spawn(async move {
                    dashboard.update_metrics().await;
                });
            }
            DashboardMessage::SelectTab(tab) => {
                *self.selected_tab.lock().unwrap() = tab;
            }
            DashboardMessage::ToggleAdvanced => {
                let mut show_advanced = self.show_advanced.lock().unwrap();
                *show_advanced = !*show_advanced;
            }
            DashboardMessage::ToggleAutoRefresh => {
                let mut auto_refresh = self.auto_refresh.lock().unwrap();
                *auto_refresh = !*auto_refresh;
            }
            DashboardMessage::RunBenchmark => {
                let benchmark = PerformanceBenchmark::new();
                let integrator = Arc::clone(&self.performance_integrator);
                tokio::spawn(async move {
                    let report = benchmark.run_full_benchmark().await;
                    info!("Benchmark completed: {:.1}% overall score", report.summary.overall_score);
                });
            }
            DashboardMessage::AcknowledgeAlert(id) => {
                if let Ok(mut alerts) = self.active_alerts.write() {
                    if let Some(alert) = alerts.iter_mut().find(|a| a.id == id) {
                        alert.acknowledged = true;
                    }
                }
            }
            DashboardMessage::ClearAlerts => {
                if let Ok(mut alerts) = self.active_alerts.write() {
                    alerts.clear();
                }
            }
            DashboardMessage::ExportReport => {
                self.export_performance_report();
            }
        }
    }

    /// Get current metrics snapshot
    pub fn get_current_metrics(&self) -> RealTimeMetrics {
        self.current_metrics.read().unwrap().clone()
    }

    /// Get active alerts
    pub fn get_active_alerts(&self) -> Vec<PerformanceAlert> {
        self.active_alerts.read().unwrap().clone()
    }

    /// Get metrics history for charts
    pub fn get_metrics_history(&self) -> Vec<RealTimeMetrics> {
        self.metrics_history.read().unwrap().iter().cloned().collect()
    }

    // Private methods

    async fn collect_current_metrics(&self) -> RealTimeMetrics {
        let performance_summary = self.performance_integrator.get_performance_metrics();
        let memory_stats = self.performance_integrator.get_memory_stats();
        let frame_stats = self.performance_integrator.render_optimizer.get_frame_stats();

        RealTimeMetrics {
            timestamp: Instant::now(),
            fps: frame_stats.average_fps,
            memory_usage_mb: memory_stats.total_allocated as f64 / 1024.0 / 1024.0,
            cpu_usage_percent: 0.0, // Would need to collect from OS
            network_requests_per_second: 0.0, // Would calculate from network stats
            active_tabs: memory_stats.tab_count,
            render_time_ms: frame_stats.frame_time_ms,
            layout_time_ms: performance_summary.average_layout_ms,
            javascript_time_ms: performance_summary.average_page_load_ms,
            cache_hit_ratio: 0.7, // Would calculate from actual cache stats
            scroll_performance: ScrollMetrics::default(),
        }
    }

    async fn check_for_alerts(&self, metrics: &RealTimeMetrics) {
        let mut new_alerts = Vec::new();

        // FPS alert
        if metrics.fps < self.config.alert_thresholds.fps_threshold {
            new_alerts.push(PerformanceAlert {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Instant::now(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::Performance,
                title: "Low Frame Rate".to_string(),
                description: format!("Frame rate is {:.1} FPS, below threshold of {:.1} FPS",
                                   metrics.fps, self.config.alert_thresholds.fps_threshold),
                current_value: metrics.fps as f64,
                threshold: self.config.alert_thresholds.fps_threshold as f64,
                acknowledged: false,
            });
        }

        // Memory alert
        if metrics.memory_usage_mb > self.config.alert_thresholds.memory_threshold_mb {
            new_alerts.push(PerformanceAlert {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Instant::now(),
                severity: AlertSeverity::Critical,
                category: AlertCategory::Memory,
                title: "High Memory Usage".to_string(),
                description: format!("Memory usage is {:.1} MB, above threshold of {:.1} MB",
                                   metrics.memory_usage_mb, self.config.alert_thresholds.memory_threshold_mb),
                current_value: metrics.memory_usage_mb,
                threshold: self.config.alert_thresholds.memory_threshold_mb,
                acknowledged: false,
            });
        }

        // Add new alerts to active alerts
        if !new_alerts.is_empty() {
            let mut alerts = self.active_alerts.write().unwrap();
            alerts.extend(new_alerts);

            // Limit number of alerts
            if alerts.len() > 50 {
                alerts.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
                alerts.truncate(50);
            }
        }
    }

    fn header_view(&self, selected_tab: DashboardTab, show_advanced: bool, auto_refresh: bool) -> Element<DashboardMessage> {
        row![
            // Title
            text("Performance Dashboard")
                .size(24)
                .style(Color::from_rgb(0.2, 0.2, 0.2)),

            Space::with_width(Length::Fill),

            // Tab buttons
            button(text("Overview"))
                .style(if selected_tab == DashboardTab::Overview { iced::theme::Button::Primary } else { iced::theme::Button::Secondary })
                .on_press(DashboardMessage::SelectTab(DashboardTab::Overview)),

            button(text("Memory"))
                .style(if selected_tab == DashboardTab::Memory { iced::theme::Button::Primary } else { iced::theme::Button::Secondary })
                .on_press(DashboardMessage::SelectTab(DashboardTab::Memory)),

            button(text("Rendering"))
                .style(if selected_tab == DashboardTab::Rendering { iced::theme::Button::Primary } else { iced::theme::Button::Secondary })
                .on_press(DashboardMessage::SelectTab(DashboardTab::Rendering)),

            button(text("Network"))
                .style(if selected_tab == DashboardTab::Network { iced::theme::Button::Primary } else { iced::theme::Button::Secondary })
                .on_press(DashboardMessage::SelectTab(DashboardTab::Network)),

            button(text("Benchmarks"))
                .style(if selected_tab == DashboardTab::Benchmarks { iced::theme::Button::Primary } else { iced::theme::Button::Secondary })
                .on_press(DashboardMessage::SelectTab(DashboardTab::Benchmarks)),

            button(text("Alerts"))
                .style(if selected_tab == DashboardTab::Alerts { iced::theme::Button::Primary } else { iced::theme::Button::Secondary })
                .on_press(DashboardMessage::SelectTab(DashboardTab::Alerts)),

            // Control buttons
            Space::with_width(Length::Fixed(20.0)),

            button(text(if auto_refresh { "Auto-refresh: ON" } else { "Auto-refresh: OFF" }))
                .on_press(DashboardMessage::ToggleAutoRefresh),

            button(text(if show_advanced { "Advanced: ON" } else { "Advanced: OFF" }))
                .on_press(DashboardMessage::ToggleAdvanced),

            button(text("Refresh"))
                .on_press(DashboardMessage::RefreshData),

            button(text("Run Benchmark"))
                .on_press(DashboardMessage::RunBenchmark),
        ]
        .align_items(Alignment::Center)
        .spacing(10)
        .into()
    }

    fn overview_view(&self) -> Element<DashboardMessage> {
        let metrics = self.get_current_metrics();
        let alerts = self.get_active_alerts();

        column![
            // Key metrics
            row![
                self.metric_card("Frame Rate", &format!("{:.1} FPS", metrics.fps), Color::from_rgb(0.0, 0.8, 0.0)),
                self.metric_card("Memory Usage", &format!("{:.1} MB", metrics.memory_usage_mb),
                               if metrics.memory_usage_mb > 500.0 { Color::from_rgb(0.8, 0.0, 0.0) } else { Color::from_rgb(0.0, 0.0, 0.8) }),
                self.metric_card("Active Tabs", &format!("{}", metrics.active_tabs), Color::from_rgb(0.0, 0.0, 0.8)),
                self.metric_card("Render Time", &format!("{:.2} ms", metrics.render_time_ms), Color::from_rgb(0.0, 0.8, 0.0)),
            ].spacing(20),

            Space::with_height(Length::Fixed(30.0)),

            // Recent alerts
            if !alerts.is_empty() {
                column![
                    text("Recent Alerts").size(18),
                    Space::with_height(Length::Fixed(10.0)),
                    scrollable(
                        column(
                            alerts.iter().take(5).map(|alert| {
                                container(row![
                                    text(match alert.severity {
                                        AlertSeverity::Critical => "🔴",
                                        AlertSeverity::Warning => "🟡",
                                        AlertSeverity::Info => "🔵",
                                    }),
                                    Space::with_width(Length::Fixed(10.0)),
                                    column![
                                        text(&alert.title).size(14),
                                        text(&alert.description).size(12),
                                    ].spacing(5),
                                    Space::with_width(Length::Fill),
                                    button(if alert.acknowledged { "Acknowledged" } else { "Acknowledge" })
                                        .on_press(DashboardMessage::AcknowledgeAlert(alert.id.clone())),
                                ].align_items(Alignment::Center))
                                .padding(10)
                                .style(match alert.severity {
                                    AlertSeverity::Critical => iced::theme::Container::Custom(Box::new(|_theme: &Theme| iced::widget::container::Appearance {
                                        text_color: None,
                                        background: Some(Color::from_rgb(1.0, 0.9, 0.9).into()),
                                        border: Border {
                                            color: Color::from_rgb(0.8, 0.0, 0.0),
                                            width: 1.0,
                                            radius: 4.0.into(),
                                        },
                                        shadow: Default::default(),
                                    })),
                                    AlertSeverity::Warning => iced::theme::Container::Custom(Box::new(|_theme: &Theme| iced::widget::container::Appearance {
                                        text_color: None,
                                        background: Some(Color::from_rgb(1.0, 1.0, 0.9).into()),
                                        border: Border {
                                            color: Color::from_rgb(0.8, 0.8, 0.0),
                                            width: 1.0,
                                            radius: 4.0.into(),
                                        },
                                        shadow: Default::default(),
                                    })),
                                    AlertSeverity::Info => iced::theme::Container::Custom(Box::new(|_theme: &Theme| iced::widget::container::Appearance {
                                        text_color: None,
                                        background: Some(Color::from_rgb(0.9, 0.9, 1.0).into()),
                                        border: Border {
                                            color: Color::from_rgb(0.0, 0.0, 0.8),
                                            width: 1.0,
                                            radius: 4.0.into(),
                                        },
                                        shadow: Default::default(),
                                    })),
                                })
                                .into()
                            })
                        ).spacing(10)
                    ).height(Length::Fixed(200.0)),
                ]
            } else {
                column![
                    text("No active alerts").size(16),
                    text("Performance is running smoothly").style(Color::from_rgb(0.0, 0.6, 0.0)),
                ]
            },
        ]
        .into()
    }

    fn memory_view(&self) -> Element<DashboardMessage> {
        let memory_stats = self.performance_integrator.get_memory_stats();

        column![
            text("Memory Usage").size(20),
            Space::with_height(Length::Fixed(20.0)),

            row![
                column![
                    text("Total Allocated"),
                    text(format!("{:.2} MB", memory_stats.total_allocated as f64 / 1024.0 / 1024.0)).size(24),
                ],
                column![
                    text("Total Freed"),
                    text(format!("{:.2} MB", memory_stats.total_freed as f64 / 1024.0 / 1024.0)).size(24),
                ],
                column![
                    text("Peak Usage"),
                    text(format!("{:.2} MB", memory_stats.peak_usage as f64 / 1024.0 / 1024.0)).size(24),
                ],
            ].spacing(40),

            Space::with_height(Length::Fixed(30.0)),

            row![
                column![
                    text("Tab Count"),
                    text(format!("{}", memory_stats.tab_count)).size(20),
                ],
                column![
                    text("Background Tabs"),
                    text(format!("{}", memory_stats.background_tabs)).size(20),
                ],
                column![
                    text("Cleanup Count"),
                    text(format!("{}", memory_stats.cleanup_count)).size(20),
                ],
            ].spacing(40),

            Space::with_height(Length::Fixed(30.0)),

            row![
                column![
                    text("Cache Hits"),
                    text(format!("{}", memory_stats.cache_hits)).size(20),
                ],
                column![
                    text("Cache Misses"),
                    text(format!("{}", memory_stats.cache_misses)).size(20),
                ],
            ].spacing(40),
        ]
        .into()
    }

    fn rendering_view(&self) -> Element<DashboardMessage> {
        let frame_stats = self.performance_integrator.render_optimizer.get_frame_stats();

        column![
            text("Rendering Performance").size(20),
            Space::with_height(Length::Fixed(20.0)),

            row![
                column![
                    text("Current FPS"),
                    text(format!("{:.1}", frame_stats.fps)).size(24),
                ],
                column![
                    text("Average FPS"),
                    text(format!("{:.1}", frame_stats.average_fps)).size(24),
                ],
                column![
                    text("Frame Time"),
                    text(format!("{:.2} ms", frame_stats.frame_time_ms)).size(24),
                ],
            ].spacing(40),

            Space::with_height(Length::Fixed(30.0)),

            row![
                column![
                    text("Min FPS"),
                    text(format!("{:.1}", frame_stats.min_fps)).size(20),
                ],
                column![
                    text("Max FPS"),
                    text(format!("{:.1}", frame_stats.max_fps)).size(20),
                ],
                column![
                    text("Dropped Frames"),
                    text(format!("{}", frame_stats.dropped_frames)).size(20),
                ],
            ].spacing(40),

            Space::with_height(Length::Fixed(30.0)),

            text("Frame Time History").size(16),
            // In a real implementation, this would show a chart
            progress_bar(0.0..=1.0, frame_stats.fps / 60.0),
        ]
        .into()
    }

    fn network_view(&self) -> Element<DashboardMessage> {
        column![
            text("Network Performance").size(20),
            Space::with_height(Length::Fixed(20.0)),

            text("Network metrics would be displayed here"),
            text("Request rates, error rates, latency, etc."),

            Space::with_height(Length::Fixed(30.0)),

            button(text("Run Network Test"))
                .on_press(DashboardMessage::RunBenchmark),
        ]
        .into()
    }

    fn benchmarks_view(&self) -> Element<DashboardMessage> {
        column![
            text("Performance Benchmarks").size(20),
            Space::with_height(Length::Fixed(20.0)),

            text("Recent benchmark results would be displayed here"),
            text("Performance trends, comparisons, and improvements"),

            Space::with_height(Length::Fixed(30.0)),

            button(text("Run Full Benchmark"))
                .on_press(DashboardMessage::RunBenchmark),

            Space::with_height(Length::Fixed(20.0)),

            button(text("Export Report"))
                .on_press(DashboardMessage::ExportReport),
        ]
        .into()
    }

    fn alerts_view(&self) -> Element<DashboardMessage, Theme, iced::Renderer> {
        let alerts = self.get_active_alerts();

        column![
            row![
                text("Performance Alerts").size(20),
                Space::with_width(Length::Fill),
                button(text("Clear All"))
                    .on_press(DashboardMessage::ClearAlerts),
            ],
            Space::with_height(Length::Fixed(20.0)),

            if alerts.is_empty() {
                column![
                    Element::<DashboardMessage, Theme, iced::Renderer>::new(Text::new("No active alerts")),
                    Element::<DashboardMessage, Theme, iced::Renderer>::new(Text::new("Performance is within acceptable thresholds")),
                ].into()
            } else {
                Element::from(scrollable(
                    column(
                        alerts.iter().map(|alert| {
                            container(column![
                                row![
                                    text(match alert.severity {
                                        AlertSeverity::Critical => "🔴 Critical",
                                        AlertSeverity::Warning => "🟡 Warning",
                                        AlertSeverity::Info => "🔵 Info",
                                    }).size(16),
                                    Space::with_width(Length::Fill),
                                    text(format!("{:.0}s ago", alert.timestamp.elapsed().as_secs()))
                                        .style(iced::theme::Text::Color(Color::from_rgb(0.5, 0.5, 0.5))),
                                ],
                                Space::with_height(Length::Fixed(10.0)),
                                text(&alert.title).size(14),
                                text(&alert.description).size(12),
                                Space::with_height(Length::Fixed(10.0)),
                                row![
                                    text(format!("Current: {:.2}", alert.current_value)),
                                    Space::with_width(Length::Fixed(20.0)),
                                    text(format!("Threshold: {:.2}", alert.threshold)),
                                    Space::with_width(Length::Fill),
                                    if !alert.acknowledged {
                                        Element::from(button(text("Acknowledge"))
                                            .on_press(DashboardMessage::AcknowledgeAlert(alert.id.clone())))
                                    } else {
                                        Element::from(text("Acknowledged")
                                            .style(iced::theme::Text::Color(Color::from_rgb(0.0, 0.6, 0.0))))
                                    }
                                ],
                            ].spacing(5))
                            .padding(15)
                            .style(match alert.severity {
                                AlertSeverity::Critical => iced::theme::Container::Custom(Box::new(|_theme: &Theme| iced::widget::container::Appearance {
                                    text_color: None,
                                    background: Some(Color::from_rgb(1.0, 0.9, 0.9).into()),
                                    border: Border {
                                        color: Color::from_rgb(0.8, 0.0, 0.0),
                                        width: 1.0,
                                        radius: 8.0.into(),
                                    },
                                    shadow: Default::default(),
                                })),
                                AlertSeverity::Warning => iced::theme::Container::Custom(Box::new(|_theme: &Theme| iced::widget::container::Appearance {
                                    text_color: None,
                                    background: Some(Color::from_rgb(1.0, 1.0, 0.9).into()),
                                    border: Border {
                                        color: Color::from_rgb(0.8, 0.8, 0.0),
                                        width: 1.0,
                                        radius: 8.0.into(),
                                    },
                                    shadow: Default::default(),
                                })),
                                AlertSeverity::Info => iced::theme::Container::Custom(Box::new(|_theme: &Theme| iced::widget::container::Appearance {
                                    text_color: None,
                                    background: Some(Color::from_rgb(0.9, 0.9, 1.0).into()),
                                    border: Border {
                                        color: Color::from_rgb(0.0, 0.0, 0.8),
                                        width: 1.0,
                                        radius: 8.0.into(),
                                    },
                                    shadow: Default::default(),
                                })),
                            })
                            .into()
                        })
                    ).spacing(15)
                ))
            },
        ]
        .into()
    }

    fn settings_view(&self) -> Element<DashboardMessage> {
        let show_advanced = *self.show_advanced.lock().unwrap();
        let auto_refresh = *self.auto_refresh.lock().unwrap();

        column![
            text("Dashboard Settings").size(20),
            Space::with_height(Length::Fixed(20.0)),

            row![
                text("Auto-refresh:"),
                Space::with_width(Length::Fixed(10.0)),
                button(text(if auto_refresh { "Enabled" } else { "Disabled" }))
                    .on_press(DashboardMessage::ToggleAutoRefresh),
            ],

            Space::with_height(Length::Fixed(20.0)),

            row![
                text("Advanced metrics:"),
                Space::with_width(Length::Fixed(10.0)),
                button(text(if show_advanced { "Enabled" } else { "Disabled" }))
                    .on_press(DashboardMessage::ToggleAdvanced),
            ],

            Space::with_height(Length::Fixed(20.0)),

            text("Alert Thresholds:").size(16),
            Space::with_height(Length::Fixed(10.0)),

            text(format!("FPS Threshold: {:.1}", self.config.alert_thresholds.fps_threshold)),
            text(format!("Memory Threshold: {:.1} MB", self.config.alert_thresholds.memory_threshold_mb)),
            text(format!("Load Time Threshold: {} ms", self.config.alert_thresholds.load_time_threshold_ms)),
        ]
        .into()
    }

    fn metric_card(&self, title: &str, value: &str, color: Color) -> Element<DashboardMessage> {
        container(column![
            text(title).size(14),
            text(value).size(20).style(color),
        ].spacing(5).align_items(Alignment::Center))
        .padding(20)
        .style(iced::theme::Container::Custom(Box::new(|_theme: &Theme| iced::widget::container::Appearance {
            text_color: None,
            background: Some(Color::from_rgb(0.95, 0.95, 0.95).into()),
            border: Border {
                color: Color::from_rgb(0.8, 0.8, 0.8),
                width: 1.0,
                radius: 8.0.into(),
            },
            shadow: Default::default(),
        })))
        .into()
    }

    fn export_performance_report(&self) {
        let metrics = self.get_current_metrics();
        let alerts = self.get_active_alerts();

        // In a real implementation, this would export to file
        info!("Exporting performance report with {} metrics and {} alerts",
              "current", alerts.len());
    }
}

impl Clone for PerformanceDashboard {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            performance_integrator: Arc::clone(&self.performance_integrator),
            current_metrics: Arc::clone(&self.current_metrics),
            metrics_history: Arc::clone(&self.metrics_history),
            current_issues: Arc::clone(&self.current_issues),
            active_alerts: Arc::clone(&self.active_alerts),
            recent_reports: Arc::clone(&self.recent_reports),
            recent_benchmarks: Arc::clone(&self.recent_benchmarks),
            selected_tab: Arc::clone(&self.selected_tab),
            show_advanced: Arc::clone(&self.show_advanced),
            auto_refresh: Arc::clone(&self.auto_refresh),
            last_update: Arc::clone(&self.last_update),
        }
    }
}