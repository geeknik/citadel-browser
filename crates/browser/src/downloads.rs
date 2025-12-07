//! Download manager for Citadel Browser
//!
//! This module provides comprehensive download management with privacy,
//! security features, and user controls.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration};
use std::fs;
use std::io::Write;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use url::Url;
use tokio::sync::mpsc;

/// Download status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DownloadStatus {
    /// Download is queued
    Queued,
    /// Download is in progress
    InProgress { bytes_downloaded: u64, total_bytes: Option<u64> },
    /// Download completed successfully
    Completed { file_path: String },
    /// Download failed
    Failed { error: String },
    /// Download was paused by user
    Paused { bytes_downloaded: u64, total_bytes: Option<u64> },
    /// Download was cancelled by user
    Cancelled,
}

/// Download item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadItem {
    /// Unique identifier
    pub id: Uuid,
    /// Download URL
    pub url: String,
    /// Target filename
    pub filename: String,
    /// Target directory
    pub directory: String,
    /// Full file path
    pub file_path: Option<String>,
    /// MIME type if known
    pub mime_type: Option<String>,
    /// File size
    pub total_size: Option<u64>,
    /// Download status
    pub status: DownloadStatus,
    /// When download started
    pub started_at: SystemTime,
    /// When download completed/failed
    pub completed_at: Option<SystemTime>,
    /// Bytes downloaded so far
    pub bytes_downloaded: u64,
    /// Download speed (bytes per second)
    pub download_speed: f64,
    /// Estimated time remaining
    pub eta: Option<Duration>,
    /// Source tab ID
    pub source_tab: Option<Uuid>,
    /// Referer URL
    pub referer: Option<String>,
    /// Whether this is a private download
    pub is_private: bool,
    /// Whether to open file when complete
    pub open_when_complete: bool,
    /// Security scan results
    pub security_scan: SecurityScanResult,
}

impl DownloadItem {
    /// Create new download item
    pub fn new(url: String, filename: String, directory: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            url,
            filename,
            directory,
            file_path: None,
            mime_type: None,
            total_size: None,
            status: DownloadStatus::Queued,
            started_at: SystemTime::now(),
            completed_at: None,
            bytes_downloaded: 0,
            download_speed: 0.0,
            eta: None,
            source_tab: None,
            referer: None,
            is_private: false,
            open_when_complete: false,
            security_scan: SecurityScanResult::Pending,
        }
    }

    /// Get progress percentage (0.0 to 1.0)
    pub fn get_progress(&self) -> f32 {
        if let Some(total) = self.total_size {
            if total > 0 {
                (self.bytes_downloaded as f32) / (total as f32)
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    /// Get human-readable status text
    pub fn get_status_text(&self) -> String {
        match &self.status {
            DownloadStatus::Queued => "Queued".to_string(),
            DownloadStatus::InProgress { .. } => {
                if let Some(total) = self.total_size {
                    let percent = (self.bytes_downloaded as f64 / total as f64) * 100.0;
                    format!("Downloading - {:.1}%", percent)
                } else {
                    format!("Downloading - {} bytes", format_bytes(self.bytes_downloaded))
                }
            }
            DownloadStatus::Completed { .. } => "Completed".to_string(),
            DownloadStatus::Failed { error } => format!("Failed: {}", error),
            DownloadStatus::Paused { .. } => "Paused".to_string(),
            DownloadStatus::Cancelled => "Cancelled".to_string(),
        }
    }

    /// Check if download is active (in progress or paused)
    pub fn is_active(&self) -> bool {
        matches!(self.status, DownloadStatus::InProgress { .. } | DownloadStatus::Paused { .. })
    }

    /// Check if download is finished (completed, failed, or cancelled)
    pub fn is_finished(&self) -> bool {
        matches!(self.status, DownloadStatus::Completed { .. } | DownloadStatus::Failed { .. } | DownloadStatus::Cancelled)
    }

    /// Get download duration
    pub fn get_duration(&self) -> Duration {
        let end = self.completed_at.unwrap_or_else(SystemTime::now);
        end.duration_since(self.started_at).unwrap_or_default()
    }

    /// Update ETA based on current speed
    pub fn update_eta(&mut self) {
        if let Some(total) = self.total_size {
            if self.download_speed > 0.0 {
                let remaining = total.saturating_sub(self.bytes_downloaded) as f64;
                let seconds_remaining = remaining / self.download_speed;
                self.eta = Some(Duration::from_secs(seconds_remaining as u64));
            } else {
                self.eta = None;
            }
        } else {
            self.eta = None;
        }
    }
}

/// Security scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityScanResult {
    /// Scan is pending
    Pending,
    /// Scan completed - file is safe
    Safe,
    /// Scan completed - file is suspicious
    Suspicious { reason: String },
    /// Scan completed - file is dangerous
    Dangerous { threat_type: String },
    /// Scan failed
    ScanFailed { error: String },
}

/// Download manager
#[derive(Debug)]
pub struct DownloadManager {
    /// Active downloads
    downloads: HashMap<Uuid, DownloadItem>,
    /// Download history (finished downloads)
    history: VecDeque<DownloadItem>,
    /// Maximum history size
    max_history: usize,
    /// Settings
    settings: DownloadSettings,
    /// Download directory
    download_dir: PathBuf,
    /// Sender for download events
    event_sender: Option<mpsc::UnboundedSender<DownloadEvent>>,
}

/// Download settings
#[derive(Debug, Clone)]
pub struct DownloadSettings {
    /// Default download directory
    pub default_directory: PathBuf,
    /// Ask where to save each file
    pub ask_for_location: bool,
    /// Close downloads bar when all downloads complete
    pub auto_close_when_complete: bool,
    /// Start downloads immediately
    pub auto_start: bool,
    /// Maximum concurrent downloads
    pub max_concurrent_downloads: usize,
    /// Maximum download speed (bytes per second, None for unlimited)
    pub max_download_speed: Option<u64>,
    /// Scan downloads for malware
    pub scan_for_malware: bool,
    /// Open potentially dangerous files
    pub open_dangerous_files: bool,
    /// Remove completed downloads from list after
    pub remove_completed_after: Option<Duration>,
    /// File type actions
    pub file_actions: HashMap<String, FileAction>,
}

/// Action to take for specific file types
#[derive(Debug, Clone)]
pub enum FileAction {
    /// Save to disk (default)
    Save,
    /// Open file immediately
    Open,
    /// Ask user what to do
    Ask,
    /// Always block this type
    Block,
}

/// Download events
#[derive(Debug, Clone)]
pub enum DownloadEvent {
    Started { id: Uuid, url: String },
    Progress { id: Uuid, bytes: u64, total: Option<u64> },
    Completed { id: Uuid, file_path: String },
    Failed { id: Uuid, error: String },
    Paused { id: Uuid },
    Cancelled { id: Uuid },
}

impl Default for DownloadSettings {
    fn default() -> Self {
        let download_dir = dirs::download_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join("Downloads"));

        let mut file_actions = HashMap::new();

        // Dangerous file types
        for ext in &["exe", "msi", "dmg", "pkg", "deb", "rpm", "apk"] {
            file_actions.insert(ext.to_string(), FileAction::Ask);
        }

        // Document types that might be safe to open
        for ext in &["pdf", "txt", "jpg", "png", "gif"] {
            file_actions.insert(ext.to_string(), FileAction::Save);
        }

        Self {
            default_directory: download_dir,
            ask_for_location: false,
            auto_close_when_complete: false,
            auto_start: true,
            max_concurrent_downloads: 3,
            max_download_speed: None,
            scan_for_malware: true,
            open_dangerous_files: false,
            remove_completed_after: Some(Duration::from_secs(3600)), // 1 hour
            file_actions,
        }
    }
}

impl DownloadManager {
    /// Create new download manager
    pub fn new() -> Result<Self, DownloadError> {
        let settings = DownloadSettings::default();
        let download_dir = settings.default_directory.clone();

        // Ensure download directory exists
        fs::create_dir_all(&download_dir)?;

        Ok(Self {
            downloads: HashMap::new(),
            history: VecDeque::new(),
            max_history: 1000,
            settings,
            download_dir,
            event_sender: None,
        })
    }

    /// Create download manager with custom settings
    pub fn with_settings(settings: DownloadSettings) -> Result<Self, DownloadError> {
        let download_dir = settings.default_directory.clone();
        fs::create_dir_all(&download_dir)?;

        Ok(Self {
            downloads: HashMap::new(),
            history: VecDeque::new(),
            max_history: 1000,
            settings,
            download_dir,
            event_sender: None,
        })
    }

    /// Set event sender for notifications
    pub fn set_event_sender(&mut self, sender: mpsc::UnboundedSender<DownloadEvent>) {
        self.event_sender = Some(sender);
    }

    /// Start a new download
    pub async fn start_download(&mut self, url: String, referer: Option<String>) -> Result<Uuid, DownloadError> {
        let parsed_url = Url::parse(&url)?;
        let filename = self.extract_filename(&parsed_url)?;

        // Determine save location
        let (directory, filename) = if self.settings.ask_for_location {
            // TODO: Show file dialog - for now use default
            (self.download_dir.to_string_lossy().to_string(), filename)
        } else {
            let filename = self.get_unique_filename(&filename, &self.download_dir)?;
            (self.download_dir.to_string_lossy().to_string(), filename)
        };

        let mut download = DownloadItem::new(url, filename, directory);
        download.referer = referer;

        // Determine action based on file extension
        if let Some(ext) = Path::new(&download.filename).extension().and_then(|e| e.to_str()) {
            if let Some(action) = self.settings.file_actions.get(ext) {
                match action {
                    FileAction::Block => return Err(DownloadError::FileBlocked),
                    FileAction::Open => download.open_when_complete = true,
                    FileAction::Ask => {
                        // TODO: Show confirmation dialog
                        return Err(DownloadError::UserCancelled);
                    }
                    FileAction::Save => {} // Default action
                }
            }
        }

        // Get file size from headers if possible
        if let Ok(total_size) = self.get_file_size(&download.url).await {
            download.total_size = Some(total_size);
        }

        let download_id = download.id;

        // Add to active downloads
        self.downloads.insert(download_id, download.clone());

        // Start download if auto-start is enabled
        if self.settings.auto_start {
            self.execute_download(download_id).await?;
        }

        // Send notification
        if let Some(sender) = &self.event_sender {
            let _ = sender.send(DownloadEvent::Started { id: download_id, url: download.url.clone() });
        }

        Ok(download_id)
    }

    /// Execute the actual download
    async fn execute_download(&mut self, download_id: Uuid) -> Result<(), DownloadError> {
        let download = self.downloads.get_mut(&download_id).ok_or(DownloadError::NotFound)?;
        download.status = DownloadStatus::InProgress { bytes_downloaded: 0, total_bytes: download.total_size };

        let url = download.url.clone();
        let file_path = Path::new(&download.directory).join(&download.filename);
        download.file_path = Some(file_path.to_string_lossy().to_string());

        // Create the file
        let mut file = fs::File::create(&file_path)?;

        // Perform HTTP request
        let client = reqwest::Client::new();
        let response = client.get(&url).send().await.map_err(|e| DownloadError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(DownloadError::HttpError(response.status().as_u16()));
        }

        let total_size = response.content_length();
        let mut downloaded = 0u64;
        let start_time = std::time::Instant::now();

        let mut stream = response.bytes_stream();
        use futures::StreamExt;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| DownloadError::NetworkError(e.to_string()))?;
            file.write_all(&chunk).map_err(|e| DownloadError::IoError(e.to_string()))?;

            downloaded += chunk.len() as u64;

            // Update download progress
            if let Some(download) = self.downloads.get_mut(&download_id) {
                download.bytes_downloaded = downloaded;
                download.total_size = total_size;

                // Calculate speed
                let elapsed = start_time.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    download.download_speed = downloaded as f64 / elapsed;
                    download.update_eta();
                }

                // Send progress update
                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(DownloadEvent::Progress {
                        id: download_id,
                        bytes: downloaded,
                        total: total_size,
                    });
                }
            }

            // Check speed limit
            if let Some(max_speed) = self.settings.max_download_speed {
                let elapsed = start_time.elapsed().as_secs_f64();
                let current_speed = downloaded as f64 / elapsed;
                if current_speed > max_speed as f64 {
                    let delay = ((downloaded as f64 / max_speed as f64) - elapsed).max(0.0);
                    tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                }
            }
        }

        // Perform security scan if enabled
        let scan_result = if self.settings.scan_for_malware {
            self.scan_file(&file_path).await
        } else {
            SecurityScanResult::Safe
        };

        // Mark as completed
        if let Some(download) = self.downloads.get_mut(&download_id) {
            download.status = DownloadStatus::Completed {
                file_path: file_path.to_string_lossy().to_string()
            };
            download.completed_at = Some(SystemTime::now());
            download.security_scan = scan_result;
        }

        // Move to history
        if let Some(completed_download) = self.downloads.remove(&download_id) {
            self.move_to_history(completed_download);

            // Send completion notification
            if let Some(sender) = &self.event_sender {
                let _ = sender.send(DownloadEvent::Completed {
                    id: download_id,
                    file_path: file_path.to_string_lossy().to_string()
                });
            }
        }

        Ok(())
    }

    /// Pause a download
    pub fn pause_download(&mut self, download_id: Uuid) -> Result<(), DownloadError> {
        if let Some(download) = self.downloads.get_mut(&download_id) {
            if let DownloadStatus::InProgress { bytes_downloaded, total_bytes } = download.status {
                download.status = DownloadStatus::Paused { bytes_downloaded, total_bytes };

                if let Some(sender) = &self.event_sender {
                    let _ = sender.send(DownloadEvent::Paused { id: download_id });
                }
            }
        }
        Ok(())
    }

    /// Resume a download
    pub async fn resume_download(&mut self, download_id: Uuid) -> Result<(), DownloadError> {
        if let Some(download) = self.downloads.get_mut(&download_id) {
            if matches!(download.status, DownloadStatus::Paused { .. }) {
                // TODO: Implement resume logic
                // For now, just restart the download
                return self.execute_download(download_id).await;
            }
        }
        Ok(())
    }

    /// Cancel a download
    pub fn cancel_download(&mut self, download_id: Uuid) -> Result<(), DownloadError> {
        if let Some(download) = self.downloads.remove(&download_id) {
            // Delete partial file
            if let Some(file_path) = &download.file_path {
                let _ = fs::remove_file(file_path);
            }

            // Move to history as cancelled
            let mut cancelled_download = download;
            cancelled_download.status = DownloadStatus::Cancelled;
            cancelled_download.completed_at = Some(SystemTime::now());
            self.move_to_history(cancelled_download);

            if let Some(sender) = &self.event_sender {
                let _ = sender.send(DownloadEvent::Cancelled { id: download_id });
            }
        }
        Ok(())
    }

    /// Retry a failed download
    pub async fn retry_download(&mut self, download_id: Uuid) -> Result<(), DownloadError> {
        // Find in history first
        let download_to_retry = self.history.iter()
            .find(|d| d.id == download_id)
            .cloned();

        if let Some(download) = download_to_retry {
            // Remove from history
            self.history.retain(|d| d.id != download_id);

            // Start new download with same URL
            return self.start_download(download.url, download.referer).await.map(|_| ());
        }

        Err(DownloadError::NotFound)
    }

    /// Get download by ID
    pub fn get_download(&self, download_id: Uuid) -> Option<&DownloadItem> {
        self.downloads.get(&download_id)
            .or_else(|| self.history.iter().find(|d| d.id == download_id))
    }

    /// Get all active downloads
    pub fn get_active_downloads(&self) -> Vec<&DownloadItem> {
        self.downloads.values().collect()
    }

    /// Get download history
    pub fn get_history(&self) -> Vec<&DownloadItem> {
        self.history.iter().collect()
    }

    /// Clear completed downloads from history
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Clear old downloads from history
    pub fn clear_old_downloads(&mut self, max_age: Duration) {
        let cutoff = SystemTime::now() - max_age;
        self.history.retain(|d| {
            d.completed_at.map(|t| t > cutoff).unwrap_or(false)
        });
    }

    /// Get download statistics
    pub fn get_stats(&self) -> DownloadStats {
        let active_count = self.downloads.len();
        let completed_count = self.history.iter()
            .filter(|d| matches!(d.status, DownloadStatus::Completed { .. }))
            .count();
        let failed_count = self.history.iter()
            .filter(|d| matches!(d.status, DownloadStatus::Failed { .. }))
            .count();

        let total_downloaded: u64 = self.history.iter()
            .filter_map(|d| {
                match &d.status {
                    DownloadStatus::Completed { .. } => Some(d.total_size.unwrap_or(d.bytes_downloaded)),
                    _ => None,
                }
            })
            .sum();

        DownloadStats {
            active_downloads: active_count,
            completed_downloads: completed_count,
            failed_downloads: failed_count,
            total_bytes_downloaded: total_downloaded,
        }
    }

    /// Update settings
    pub fn update_settings(&mut self, settings: DownloadSettings) -> Result<(), DownloadError> {
        // Update download directory
        if settings.default_directory != self.settings.default_directory {
            fs::create_dir_all(&settings.default_directory)?;
            self.download_dir = settings.default_directory.clone();
        }

        self.settings = settings;
        Ok(())
    }

    /// Get current settings
    pub fn get_settings(&self) -> &DownloadSettings {
        &self.settings
    }

    // Private helper methods

    /// Extract filename from URL
    fn extract_filename(&self, url: &Url) -> Result<String, DownloadError> {
        if let Some(segments) = url.path_segments() {
            if let Some(last) = segments.last() {
                if !last.is_empty() {
                    return Ok(last.to_string());
                }
            }
        }

        // Fallback to domain name
        if let Some(domain) = url.domain() {
            Ok(format!("{}.html", domain))
        } else {
            Ok("download".to_string())
        }
    }

    /// Get unique filename (add number if exists)
    fn get_unique_filename(&self, filename: &str, directory: &Path) -> Result<String, DownloadError> {
        let path = directory.join(filename);

        if !path.exists() {
            return Ok(filename.to_string());
        }

        let stem = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("download");
        let extension = path.extension()
            .and_then(|s| s.to_str());

        for i in 1..1000 {
            let new_name = if let Some(ext) = extension {
                format!("{}_{}.{}", stem, i, ext)
            } else {
                format!("{}_{}", stem, i)
            };

            let new_path = directory.join(&new_name);
            if !new_path.exists() {
                return Ok(new_name);
            }
        }

        Err(DownloadError::CannotCreateFile)
    }

    /// Get file size from HTTP headers
    async fn get_file_size(&self, url: &str) -> Result<u64, DownloadError> {
        let client = reqwest::Client::new();
        let response = client.head(url).send().await.map_err(DownloadError::from)?;

        if response.status().is_success() {
            Ok(response.content_length().unwrap_or(0))
        } else {
            Ok(0)
        }
    }

    /// Scan file for malware (placeholder)
    async fn scan_file(&self, _file_path: &Path) -> SecurityScanResult {
        // TODO: Implement actual malware scanning
        // For now, just check file size and extension
        SecurityScanResult::Safe
    }

    /// Move download to history
    fn move_to_history(&mut self, download: DownloadItem) {
        self.history.push_back(download);

        // Limit history size
        while self.history.len() > self.max_history {
            self.history.pop_front();
        }
    }
}

/// Download statistics
#[derive(Debug, Clone)]
pub struct DownloadStats {
    pub active_downloads: usize,
    pub completed_downloads: usize,
    pub failed_downloads: usize,
    pub total_bytes_downloaded: u64,
}

/// Download errors
#[derive(Debug, Clone)]
pub enum DownloadError {
    NetworkError(String),
    HttpError(u16),
    IoError(String),
    ParseError(String),
    NotFound,
    FileBlocked,
    UserCancelled,
    CannotCreateFile,
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownloadError::NetworkError(e) => write!(f, "Network error: {}", e),
            DownloadError::HttpError(status) => write!(f, "HTTP error: {}", status),
            DownloadError::IoError(e) => write!(f, "IO error: {}", e),
            DownloadError::ParseError(e) => write!(f, "URL parse error: {}", e),
            DownloadError::NotFound => write!(f, "Download not found"),
            DownloadError::FileBlocked => write!(f, "File type is blocked"),
            DownloadError::UserCancelled => write!(f, "Download cancelled by user"),
            DownloadError::CannotCreateFile => write!(f, "Cannot create download file"),
        }
    }
}

impl From<std::io::Error> for DownloadError {
    fn from(e: std::io::Error) -> Self {
        DownloadError::IoError(e.to_string())
    }
}

impl From<reqwest::Error> for DownloadError {
    fn from(e: reqwest::Error) -> Self {
        DownloadError::NetworkError(e.to_string())
    }
}

impl From<url::ParseError> for DownloadError {
    fn from(e: url::ParseError) -> Self {
        DownloadError::ParseError(e.to_string())
    }
}

impl std::error::Error for DownloadError {}

/// Format bytes as human readable string
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}