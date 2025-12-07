//! Navigation history management for Citadel Browser
//!
//! This module provides comprehensive navigation history with privacy-preserving features,
//! session management, and efficient storage.

use std::collections::VecDeque;
use std::time::{SystemTime, Duration};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Maximum number of history entries per tab
const MAX_HISTORY_ENTRIES: usize = 100;

/// Maximum number of global history entries
const MAX_GLOBAL_HISTORY: usize = 10000;

/// History entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unique identifier for this entry
    pub id: Uuid,
    /// URL of the page
    pub url: String,
    /// Page title
    pub title: String,
    /// Timestamp when this entry was created
    pub timestamp: SystemTime,
    /// How this entry was reached
    pub transition_type: TransitionType,
    /// Whether this entry should be saved in persistent storage
    pub should_persist: bool,
    /// Security level of the page
    pub security_level: SecurityLevel,
}

/// How the user navigated to this page
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionType {
    /// User typed the URL or selected from bookmarks
    Typed,
    /// User clicked a link
    Link,
    /// User navigated forward or backward
    Forward,
    Backward,
    /// Page was reloaded
    Reload,
    /// Browser restored this page from a previous session
    Restore,
    /// Form submission
    FormSubmit,
    /// JavaScript redirection
    Redirect,
    /// Page was opened in a new tab
    NewTab,
}

/// Security level of the page
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// HTTPS with valid certificate
    Secure,
    /// HTTPS with certificate issues
    Warning,
    /// HTTP connection (insecure)
    Insecure,
    /// Local file
    Local,
    /// Error page
    Error,
}

/// Per-tab navigation history
#[derive(Debug, Clone)]
pub struct TabHistory {
    /// Unique identifier for this tab
    pub tab_id: Uuid,
    /// History stack for this tab
    entries: VecDeque<HistoryEntry>,
    /// Current position in the history stack
    current_index: usize,
    /// Maximum entries for this tab
    max_entries: usize,
}

impl TabHistory {
    /// Create new tab history
    pub fn new(tab_id: Uuid) -> Self {
        Self {
            tab_id,
            entries: VecDeque::with_capacity(MAX_HISTORY_ENTRIES),
            current_index: 0,
            max_entries: MAX_HISTORY_ENTRIES,
        }
    }

    /// Add a new entry to history
    pub fn add_entry(&mut self, entry: HistoryEntry) {
        // Remove all entries after current position (forward history)
        while self.entries.len() > self.current_index + 1 {
            self.entries.pop_back();
        }

        // Add new entry
        self.entries.push_back(entry);
        self.current_index = self.entries.len() - 1;

        // Limit history size
        if self.entries.len() > self.max_entries {
            self.entries.pop_front();
            self.current_index -= 1;
        }
    }

    /// Get current entry
    pub fn current_entry(&self) -> Option<&HistoryEntry> {
        self.entries.get(self.current_index)
    }

    /// Go back in history
    pub fn go_back(&mut self) -> Option<&HistoryEntry> {
        if self.can_go_back() {
            self.current_index -= 1;
            self.current_entry()
        } else {
            None
        }
    }

    /// Go forward in history
    pub fn go_forward(&mut self) -> Option<&HistoryEntry> {
        if self.can_go_forward() {
            self.current_index += 1;
            self.current_entry()
        } else {
            None
        }
    }

    /// Check if we can go back
    pub fn can_go_back(&self) -> bool {
        self.current_index > 0
    }

    /// Check if we can go forward
    pub fn can_go_forward(&self) -> bool {
        self.current_index < self.entries.len() - 1
    }

    /// Get all entries for this tab
    pub fn get_entries(&self) -> Vec<&HistoryEntry> {
        self.entries.iter().collect()
    }

    /// Clear history for this tab
    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_index = 0;
    }

    /// Get the index of current entry
    pub fn current_index(&self) -> usize {
        self.current_index
    }

    /// Get total number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if history is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Global browser history with privacy features
#[derive(Debug, Clone)]
pub struct GlobalHistory {
    /// All history entries across all tabs
    entries: VecDeque<HistoryEntry>,
    /// Maximum number of global entries
    max_entries: usize,
    /// Privacy settings
    privacy_settings: HistoryPrivacySettings,
    /// When to automatically clear history
    auto_clear_policy: AutoClearPolicy,
    /// Last time history was cleared
    last_cleared: SystemTime,
}

impl Default for GlobalHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalHistory {
    /// Create new global history
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_GLOBAL_HISTORY),
            max_entries: MAX_GLOBAL_HISTORY,
            privacy_settings: HistoryPrivacySettings::default(),
            auto_clear_policy: AutoClearPolicy::Never,
            last_cleared: SystemTime::now(),
        }
    }

    /// Add entry to global history
    pub fn add_entry(&mut self, entry: HistoryEntry) {
        // Skip private entries if configured
        if !self.privacy_settings.include_private && !entry.should_persist {
            return;
        }

        // Skip sensitive URLs
        if self.privacy_settings.exclude_sensitive && self.is_sensitive_url(&entry.url) {
            return;
        }

        // Skip error pages if configured
        if !self.privacy_settings.include_errors && matches!(entry.security_level, SecurityLevel::Error) {
            return;
        }

        self.entries.push_back(entry);

        // Limit history size
        if self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    /// Search history by text
    pub fn search(&self, query: &str) -> Vec<&HistoryEntry> {
        let query_lower = query.to_lowercase();
        self.entries
            .iter()
            .filter(|entry| {
                entry.title.to_lowercase().contains(&query_lower) ||
                entry.url.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Get entries from a specific time range
    pub fn get_entries_by_time_range(&self, start: SystemTime, end: SystemTime) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.timestamp >= start && entry.timestamp <= end)
            .collect()
    }

    /// Get most recent entries
    pub fn get_recent(&self, limit: usize) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .rev()
            .take(limit)
            .collect()
    }

    /// Get all entries
    pub fn get_all(&self) -> Vec<&HistoryEntry> {
        self.entries.iter().collect()
    }

    /// Clear all history
    pub fn clear(&mut self) {
        self.entries.clear();
        self.last_cleared = SystemTime::now();
    }

    /// Clear entries older than specified duration
    pub fn clear_older_than(&mut self, duration: Duration) {
        let cutoff = SystemTime::now() - duration;
        self.entries.retain(|entry| entry.timestamp >= cutoff);
    }

    /// Remove specific entry
    pub fn remove_entry(&mut self, id: Uuid) -> bool {
        let original_len = self.entries.len();
        self.entries.retain(|entry| entry.id != id);
        self.entries.len() < original_len
    }

    /// Get history statistics
    pub fn get_stats(&self) -> HistoryStats {
        let total_entries = self.entries.len();
        let secure_entries = self.entries
            .iter()
            .filter(|e| matches!(e.security_level, SecurityLevel::Secure))
            .count();
        let insecure_entries = self.entries
            .iter()
            .filter(|e| matches!(e.security_level, SecurityLevel::Insecure))
            .count();
        let warning_entries = self.entries
            .iter()
            .filter(|e| matches!(e.security_level, SecurityLevel::Warning))
            .count();

        HistoryStats {
            total_entries,
            secure_entries,
            insecure_entries,
            warning_entries,
            last_cleared: self.last_cleared,
        }
    }

    /// Check if auto-clear should happen
    pub fn should_auto_clear(&self) -> bool {
        match self.auto_clear_policy {
            AutoClearPolicy::Never => false,
            AutoClearPolicy::OnExit => false, // Handled by the caller
            AutoClearPolicy::Daily => {
                SystemTime::now().duration_since(self.last_cleared).unwrap_or(Duration::ZERO) >= Duration::from_secs(86400)
            }
            AutoClearPolicy::Weekly => {
                SystemTime::now().duration_since(self.last_cleared).unwrap_or(Duration::ZERO) >= Duration::from_secs(604800)
            }
            AutoClearPolicy::Monthly => {
                SystemTime::now().duration_since(self.last_cleared).unwrap_or(Duration::ZERO) >= Duration::from_secs(2592000)
            }
        }
    }

    /// Apply auto-clear if needed
    pub fn apply_auto_clear(&mut self) {
        if self.should_auto_clear() {
            self.clear();
        }
    }

    /// Set privacy settings
    pub fn set_privacy_settings(&mut self, settings: HistoryPrivacySettings) {
        self.privacy_settings = settings;
    }

    /// Set auto-clear policy
    pub fn set_auto_clear_policy(&mut self, policy: AutoClearPolicy) {
        self.auto_clear_policy = policy;
    }

    /// Check if URL should be considered sensitive
    fn is_sensitive_url(&self, url: &str) -> bool {
        // Common sensitive patterns
        let sensitive_patterns = [
            "password",
            "login",
            "auth",
            "token",
            "session",
            "key",
            "secret",
            "credential",
        ];

        let url_lower = url.to_lowercase();

        // Check for sensitive keywords
        for pattern in &sensitive_patterns {
            if url_lower.contains(pattern) {
                return true;
            }
        }

        // Check for common sensitive domains
        let sensitive_domains = [
            "bank",
            "finance",
            "payment",
            "wallet",
        ];

        for domain in &sensitive_domains {
            if url_lower.contains(domain) {
                return true;
            }
        }

        false
    }
}

/// Privacy settings for history
#[derive(Debug, Clone)]
pub struct HistoryPrivacySettings {
    /// Include private browsing entries
    pub include_private: bool,
    /// Include error pages
    pub include_errors: bool,
    /// Exclude potentially sensitive URLs
    pub exclude_sensitive: bool,
    /// Allow search suggestions from history
    pub allow_suggestions: bool,
}

impl Default for HistoryPrivacySettings {
    fn default() -> Self {
        Self {
            include_private: false,
            include_errors: false,
            exclude_sensitive: true,
            allow_suggestions: true,
        }
    }
}

/// Auto-clear policies
#[derive(Debug, Clone)]
pub enum AutoClearPolicy {
    Never,
    OnExit,
    Daily,
    Weekly,
    Monthly,
}

/// History statistics
#[derive(Debug, Clone)]
pub struct HistoryStats {
    pub total_entries: usize,
    pub secure_entries: usize,
    pub insecure_entries: usize,
    pub warning_entries: usize,
    pub last_cleared: SystemTime,
}

/// Navigation manager that coordinates tab and global history
#[derive(Debug)]
pub struct NavigationManager {
    /// Per-tab histories
    tab_histories: HashMap<Uuid, TabHistory>,
    /// Global history
    global_history: GlobalHistory,
}

impl Default for NavigationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NavigationManager {
    /// Create new navigation manager
    pub fn new() -> Self {
        Self {
            tab_histories: HashMap::new(),
            global_history: GlobalHistory::new(),
        }
    }

    /// Create or get tab history
    pub fn get_or_create_tab_history(&mut self, tab_id: Uuid) -> &mut TabHistory {
        self.tab_histories.entry(tab_id).or_insert_with(|| TabHistory::new(tab_id))
    }

    /// Navigate to URL in tab
    pub fn navigate_to(&mut self, tab_id: Uuid, url: String, title: String, transition_type: TransitionType) {
        let entry = HistoryEntry {
            id: Uuid::new_v4(),
            url: url.clone(),
            title: title.clone(),
            timestamp: SystemTime::now(),
            transition_type,
            should_persist: !url.starts_with("about:") && !url.starts_with("data:"),
            security_level: if url.starts_with("https://") {
                SecurityLevel::Secure
            } else if url.starts_with("http://") {
                SecurityLevel::Insecure
            } else if url.starts_with("file://") {
                SecurityLevel::Local
            } else {
                SecurityLevel::Error
            },
        };

        // Add to tab history
        self.get_or_create_tab_history(tab_id).add_entry(entry.clone());

        // Add to global history
        self.global_history.add_entry(entry);
    }

    /// Go back in tab history
    pub fn go_back(&mut self, tab_id: Uuid) -> Option<&HistoryEntry> {
        self.tab_histories.get_mut(&tab_id)?.go_back()
    }

    /// Go forward in tab history
    pub fn go_forward(&mut self, tab_id: Uuid) -> Option<&HistoryEntry> {
        self.tab_histories.get_mut(&tab_id)?.go_forward()
    }

    /// Check if tab can go back
    pub fn can_go_back(&self, tab_id: Uuid) -> bool {
        self.tab_histories.get(&tab_id).map(|h| h.can_go_back()).unwrap_or(false)
    }

    /// Check if tab can go forward
    pub fn can_go_forward(&self, tab_id: Uuid) -> bool {
        self.tab_histories.get(&tab_id).map(|h| h.can_go_forward()).unwrap_or(false)
    }

    /// Get current entry for tab
    pub fn get_current_entry(&self, tab_id: Uuid) -> Option<&HistoryEntry> {
        self.tab_histories.get(&tab_id)?.current_entry()
    }

    /// Get global history
    pub fn get_global_history(&self) -> &GlobalHistory {
        &self.global_history
    }

    /// Get mutable global history
    pub fn get_global_history_mut(&mut self) -> &mut GlobalHistory {
        &mut self.global_history
    }

    /// Clear tab history
    pub fn clear_tab_history(&mut self, tab_id: Uuid) {
        if let Some(history) = self.tab_histories.get_mut(&tab_id) {
            history.clear();
        }
    }

    /// Remove tab history entirely
    pub fn remove_tab(&mut self, tab_id: Uuid) {
        self.tab_histories.remove(&tab_id);
    }

    /// Get all tab histories
    pub fn get_all_tab_histories(&self) -> &HashMap<Uuid, TabHistory> {
        &self.tab_histories
    }

    /// Search global history
    pub fn search_global(&self, query: &str) -> Vec<&HistoryEntry> {
        self.global_history.search(query)
    }

    /// Get navigation suggestions
    pub fn get_suggestions(&self, partial_url: &str, limit: usize) -> Vec<&HistoryEntry> {
        if !self.global_history.privacy_settings.allow_suggestions {
            return Vec::new();
        }

        let url_lower = partial_url.to_lowercase();
        self.global_history
            .get_recent(limit * 2) // Get more to filter better
            .into_iter()
            .filter(|entry| {
                entry.url.to_lowercase().contains(&url_lower) ||
                entry.title.to_lowercase().contains(&url_lower)
            })
            .take(limit)
            .collect()
    }
}

use std::collections::HashMap;