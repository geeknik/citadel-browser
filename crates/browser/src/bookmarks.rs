//! Bookmark management system for Citadel Browser
//!
//! This module provides comprehensive bookmark management with categories,
//! tags, search functionality, and privacy-preserving features.

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Maximum number of bookmarks per folder
const MAX_BOOKMARKS_PER_FOLDER: usize = 1000;

/// Bookmark with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    /// Unique identifier
    pub id: Uuid,
    /// URL of the bookmark
    pub url: String,
    /// Bookmark title
    pub title: String,
    /// Description (optional)
    pub description: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Folder this bookmark belongs to
    pub folder_id: Option<Uuid>,
    /// When this bookmark was created
    pub created_at: SystemTime,
    /// When this bookmark was last accessed
    pub last_accessed: Option<SystemTime>,
    /// Number of times this bookmark was accessed
    pub access_count: u64,
    /// Whether this bookmark is private
    pub is_private: bool,
    /// Bookmark favicon URL (optional)
    pub favicon_url: Option<String>,
    /// Custom sort order
    pub sort_order: Option<i32>,
}

impl Bookmark {
    /// Create new bookmark
    pub fn new(url: String, title: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            url,
            title,
            description: None,
            tags: Vec::new(),
            folder_id: None,
            created_at: SystemTime::now(),
            last_accessed: None,
            access_count: 0,
            is_private: false,
            favicon_url: None,
            sort_order: None,
        }
    }

    /// Mark bookmark as accessed
    pub fn mark_accessed(&mut self) {
        self.last_accessed = Some(SystemTime::now());
        self.access_count += 1;
    }

    /// Add tag to bookmark
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Remove tag from bookmark
    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
    }

    /// Check if bookmark has specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(&tag.to_string())
    }

    /// Move bookmark to folder
    pub fn move_to_folder(&mut self, folder_id: Option<Uuid>) {
        self.folder_id = folder_id;
    }

    /// Set bookmark as private/public
    pub fn set_private(&mut self, is_private: bool) {
        self.is_private = is_private;
    }

    /// Get bookmark's relevance score for search
    pub fn get_relevance_score(&self, query: &str) -> f32 {
        let query_lower = query.to_lowercase();
        let title_lower = self.title.to_lowercase();
        let url_lower = self.url.to_lowercase();

        let mut score = 0.0;

        // Exact title match gets highest score
        if title_lower == query_lower {
            score += 100.0;
        }

        // Title contains query
        if title_lower.contains(&query_lower) {
            score += 50.0;
        }

        // URL contains query
        if url_lower.contains(&query_lower) {
            score += 30.0;
        }

        // Tag matches
        for tag in &self.tags {
            if tag.to_lowercase().contains(&query_lower) {
                score += 20.0;
            }
        }

        // Description match
        if let Some(ref desc) = self.description {
            if desc.to_lowercase().contains(&query_lower) {
                score += 10.0;
            }
        }

        // Boost frequently accessed bookmarks
        score += (self.access_count as f32).log(2.0);

        // Boost recently accessed bookmarks
        if let Some(last_accessed) = self.last_accessed {
            let days_since_access = SystemTime::now()
                .duration_since(last_accessed)
                .unwrap_or_default()
                .as_secs() / 86400;

            if days_since_access < 7 {
                score += 10.0 - (days_since_access as f32);
            }
        }

        score
    }
}

/// Bookmark folder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkFolder {
    /// Unique identifier
    pub id: Uuid,
    /// Folder name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Parent folder (None for root)
    pub parent_id: Option<Uuid>,
    /// Child folders
    pub child_folders: Vec<Uuid>,
    /// Direct bookmarks in this folder
    pub bookmarks: Vec<Uuid>,
    /// When this folder was created
    pub created_at: SystemTime,
    /// Whether this folder is expanded in UI
    pub is_expanded: bool,
    /// Custom sort order
    pub sort_order: Option<i32>,
    /// Whether this folder is private
    pub is_private: bool,
}

impl BookmarkFolder {
    /// Create new folder
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            parent_id: None,
            child_folders: Vec::new(),
            bookmarks: Vec::new(),
            created_at: SystemTime::now(),
            is_expanded: true,
            sort_order: None,
            is_private: false,
        }
    }

    /// Add child folder
    pub fn add_child_folder(&mut self, folder_id: Uuid) {
        if !self.child_folders.contains(&folder_id) {
            self.child_folders.push(folder_id);
        }
    }

    /// Remove child folder
    pub fn remove_child_folder(&mut self, folder_id: Uuid) {
        self.child_folders.retain(|id| *id != folder_id);
    }

    /// Add bookmark to folder
    pub fn add_bookmark(&mut self, bookmark_id: Uuid) {
        if !self.bookmarks.contains(&bookmark_id) {
            self.bookmarks.push(bookmark_id);
        }
    }

    /// Remove bookmark from folder
    pub fn remove_bookmark(&mut self, bookmark_id: Uuid) {
        self.bookmarks.retain(|id| *id != bookmark_id);
    }

    /// Check if folder is descendant of another folder
    pub fn is_descendant_of(&self, folders: &HashMap<Uuid, BookmarkFolder>, ancestor_id: Uuid) -> bool {
        if let Some(parent_id) = self.parent_id {
            if parent_id == ancestor_id {
                return true;
            }
            if let Some(parent_folder) = folders.get(&parent_id) {
                return parent_folder.is_descendant_of(folders, ancestor_id);
            }
        }
        false
    }

    /// Get folder path (breadcrumb)
    pub fn get_path(&self, folders: &HashMap<Uuid, BookmarkFolder>) -> String {
        let mut path_parts = Vec::new();
        let mut current_id = Some(self.id);

        while let Some(folder_id) = current_id {
            if let Some(folder) = folders.get(&folder_id) {
                path_parts.insert(0, folder.name.clone());
                current_id = folder.parent_id;
            } else {
                break;
            }
        }

        path_parts.join(" / ")
    }

    /// Count total bookmarks in this folder and subfolders
    pub fn count_all_bookmarks(&self, folders: &HashMap<Uuid, BookmarkFolder>, bookmarks: &HashMap<Uuid, Bookmark>) -> usize {
        let mut count = self.bookmarks.len();

        for child_id in &self.child_folders {
            if let Some(child_folder) = folders.get(child_id) {
                count += child_folder.count_all_bookmarks(folders, bookmarks);
            }
        }

        count
    }
}

/// Bookmark manager
#[derive(Debug)]
pub struct BookmarkManager {
    /// All bookmarks
    bookmarks: HashMap<Uuid, Bookmark>,
    /// All folders
    folders: HashMap<Uuid, BookmarkFolder>,
    /// Root folders
    root_folders: Vec<Uuid>,
    /// Search index for fast lookup
    search_index: HashMap<String, Vec<Uuid>>,
    /// Popular tags
    popular_tags: std::collections::BTreeMap<String, usize>,
    /// Settings
    settings: BookmarkSettings,
}

/// Bookmark management settings
#[derive(Debug, Clone)]
pub struct BookmarkSettings {
    /// Maximum bookmarks per folder
    pub max_bookmarks_per_folder: usize,
    /// Whether to save favicons
    pub save_favicons: bool,
    /// Whether to auto-tag based on content
    pub auto_tag: bool,
    /// Default privacy for new bookmarks
    pub default_private: bool,
    /// Whether to suggest bookmarks in address bar
    pub suggest_in_address_bar: bool,
    /// Maximum suggestions to show
    pub max_suggestions: usize,
}

impl Default for BookmarkSettings {
    fn default() -> Self {
        Self {
            max_bookmarks_per_folder: MAX_BOOKMARKS_PER_FOLDER,
            save_favicons: true,
            auto_tag: true,
            default_private: false,
            suggest_in_address_bar: true,
            max_suggestions: 10,
        }
    }
}

impl Default for BookmarkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BookmarkManager {
    /// Create new bookmark manager
    pub fn new() -> Self {
        let mut manager = Self {
            bookmarks: HashMap::new(),
            folders: HashMap::new(),
            root_folders: Vec::new(),
            search_index: HashMap::new(),
            popular_tags: std::collections::BTreeMap::new(),
            settings: BookmarkSettings::default(),
        };

        // Create default folders
        manager.create_default_folders();
        manager
    }

    /// Create default bookmark folders
    fn create_default_folders(&mut self) {
        let bookmarks_bar = self.create_folder("Bookmarks Bar".to_string(), None);
        let other_bookmarks = self.create_folder("Other Bookmarks".to_string(), None);
        let mobile_bookmarks = self.create_folder("Mobile Bookmarks".to_string(), None);

        self.root_folders = vec![bookmarks_bar, other_bookmarks, mobile_bookmarks];
    }

    /// Create new folder
    pub fn create_folder(&mut self, name: String, parent_id: Option<Uuid>) -> Uuid {
        let folder = BookmarkFolder::new(name.clone());
        let folder_id = folder.id;

        // Add to parent if specified
        if let Some(parent_id) = parent_id {
            if let Some(parent) = self.folders.get_mut(&parent_id) {
                parent.add_child_folder(folder_id);
            }
        } else {
            self.root_folders.push(folder_id);
        }

        self.folders.insert(folder_id, folder);
        log::info!("Created bookmark folder: {}", name);
        folder_id
    }

    /// Add new bookmark
    pub fn add_bookmark(&mut self, mut bookmark: Bookmark) -> Result<Uuid, BookmarkError> {
        // Check if URL already bookmarked
        if self.bookmarks.values().any(|b| b.url == bookmark.url) {
            return Err(BookmarkError::AlreadyBookmarked);
        }

        // Apply default settings
        bookmark.is_private = bookmark.is_private || self.settings.default_private;

        // Auto-tag if enabled
        if self.settings.auto_tag {
            self.auto_tag_bookmark(&mut bookmark);
        }

        let bookmark_id = bookmark.id;

        // Add to storage
        self.bookmarks.insert(bookmark_id, bookmark.clone());

        // Add to default folder if none specified
        let folder_id = bookmark.folder_id.unwrap_or_else(|| {
            // Use "Other Bookmarks" as default
            self.root_folders.get(1).copied().unwrap_or_else(|| {
                self.create_folder("Other Bookmarks".to_string(), None)
            })
        });

        self.add_bookmark_to_folder(bookmark_id, folder_id)?;

        // Update search index
        self.update_search_index(&bookmark);

        // Update tag counts
        for tag in &bookmark.tags {
            *self.popular_tags.entry(tag.clone()).or_insert(0) += 1;
        }

        log::info!("Added bookmark: {} ({})", bookmark.title, bookmark.url);
        Ok(bookmark_id)
    }

    /// Add existing bookmark to folder
    fn add_bookmark_to_folder(&mut self, bookmark_id: Uuid, folder_id: Uuid) -> Result<(), BookmarkError> {
        if let Some(folder) = self.folders.get_mut(&folder_id) {
            if folder.bookmarks.len() >= self.settings.max_bookmarks_per_folder {
                return Err(BookmarkError::FolderFull);
            }
            folder.add_bookmark(bookmark_id);
            Ok(())
        } else {
            Err(BookmarkError::FolderNotFound)
        }
    }

    /// Auto-tag bookmark based on URL and title
    fn auto_tag_bookmark(&mut self, bookmark: &mut Bookmark) {
        let url_lower = bookmark.url.to_lowercase();
        let title_lower = bookmark.title.to_lowercase();

        // Common tag patterns
        let tag_patterns = [
            ("news", vec!["news", "article", "blog"]),
            ("social", vec!["twitter", "facebook", "instagram", "linkedin", "reddit"]),
            ("video", vec!["youtube", "vimeo", "netflix", "video"]),
            ("shopping", vec!["amazon", "ebay", "shop", "store", "buy"]),
            ("tech", vec!["github", "stackoverflow", "developer", "programming", "code"]),
            ("reference", vec!["wiki", "documentation", "manual", "guide"]),
            ("finance", vec!["bank", "finance", "money", "investment"]),
            ("work", vec!["work", "office", "professional", "business"]),
        ];

        for (tag, keywords) in &tag_patterns {
            for keyword in keywords {
                if url_lower.contains(keyword) || title_lower.contains(keyword) {
                    bookmark.add_tag(tag.to_string());
                    break;
                }
            }
        }

        // Domain-based tagging
        if let Ok(url) = url::Url::parse(&bookmark.url) {
            if let Some(domain) = url.domain() {
                bookmark.add_tag(domain.to_string());
            }
        }
    }

    /// Update search index for bookmark
    fn update_search_index(&mut self, bookmark: &Bookmark) {
        let words: Vec<String> = bookmark.title
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .chain(bookmark.tags.iter().map(|t| t.to_lowercase()))
            .collect();

        for word in words {
            self.search_index.entry(word).or_insert_with(Vec::new).push(bookmark.id);
        }
    }

    /// Get bookmark by ID
    pub fn get_bookmark(&self, id: Uuid) -> Option<&Bookmark> {
        self.bookmarks.get(&id)
    }

    /// Get folder by ID
    pub fn get_folder(&self, id: Uuid) -> Option<&BookmarkFolder> {
        self.folders.get(&id)
    }

    /// Update bookmark
    pub fn update_bookmark(&mut self, id: Uuid, updates: BookmarkUpdate) -> Result<(), BookmarkError> {
        // First check if bookmark exists
        if !self.bookmarks.contains_key(&id) {
            return Err(BookmarkError::NotFound);
        }

        // Update simple fields
        if let Some(title) = &updates.title {
            self.bookmarks.get_mut(&id).unwrap().title = title.clone();
        }

        if let Some(url) = &updates.url {
            self.bookmarks.get_mut(&id).unwrap().url = url.clone();
        }

        if let Some(description) = &updates.description {
            self.bookmarks.get_mut(&id).unwrap().description = Some(description.clone());
        }

        // Handle tags update
        if let Some(tags) = &updates.tags {
            // Get old tags to decrement counts
            let old_tags = self.bookmarks.get(&id).unwrap().tags.clone();
            
            // Remove old tag counts
            for tag in &old_tags {
                if let Some(count) = self.popular_tags.get_mut(tag) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.popular_tags.remove(tag);
                    }
                }
            }

            // Update bookmark tags
            self.bookmarks.get_mut(&id).unwrap().tags = tags.clone();

            // Add new tag counts
            for tag in tags {
                *self.popular_tags.entry(tag.clone()).or_insert(0) += 1;
            }
        }

        // Handle folder update
        if let Some(folder_id) = updates.folder_id {
            // Get old folder ID
            let old_folder_id = self.bookmarks.get(&id).unwrap().folder_id;
            
            // Remove from old folder
            if let Some(old_id) = old_folder_id {
                if let Some(old_folder) = self.folders.get_mut(&old_id) {
                    old_folder.remove_bookmark(id);
                }
            }

            // Add to new folder - this calls self methods so we can't hold bookmark ref
            self.add_bookmark_to_folder(id, folder_id)?;
            
            // Update bookmark folder_id
            self.bookmarks.get_mut(&id).unwrap().folder_id = Some(folder_id);
        }

        let title = self.bookmarks.get(&id).unwrap().title.clone();
        log::info!("Updated bookmark: {}", title);
        Ok(())
    }
// ...
    /// Search bookmarks
    pub fn search(&self, query: &str, limit: Option<usize>) -> Vec<&Bookmark> {
        if query.is_empty() {
            return Vec::new();
        }

        // Removed unused query_lower
        let mut results: Vec<_> = self.bookmarks
            .values()
            .filter(|b| !b.is_private)
            .map(|b| (b, b.get_relevance_score(query)))
            .filter(|(_, score)| *score > 0.0)
            .collect();

        // Sort by relevance score
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Return just the bookmarks, limited if specified
        results
            .into_iter()
            .map(|(bookmark, _)| bookmark)
            .take(limit.unwrap_or(50))
            .collect()
    }

    /// Get suggestions for address bar
    pub fn get_suggestions(&self, partial_url: &str) -> Vec<&Bookmark> {
        if !self.settings.suggest_in_address_bar {
            return Vec::new();
        }

        let partial_lower = partial_url.to_lowercase();

        self.bookmarks
            .values()
            .filter(|b| !b.is_private)
            .filter(|b| {
                b.url.to_lowercase().contains(&partial_lower) ||
                b.title.to_lowercase().contains(&partial_lower)
            })
            .take(self.settings.max_suggestions)
            .collect()
    }

    /// Get bookmarks in folder
    pub fn get_bookmarks_in_folder(&self, folder_id: Uuid) -> Vec<&Bookmark> {
        self.folders
            .get(&folder_id)
            .map(|folder| {
                folder.bookmarks
                    .iter()
                    .filter_map(|id| self.bookmarks.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get folder tree structure
    pub fn get_folder_tree(&self) -> Vec<&BookmarkFolder> {
        self.root_folders
            .iter()
            .filter_map(|id| self.folders.get(id))
            .collect()
    }

    /// Get all bookmarks
    pub fn get_all_bookmarks(&self) -> Vec<&Bookmark> {
        self.bookmarks.values().collect()
    }

    /// Get recently added bookmarks
    pub fn get_recent_bookmarks(&self, limit: usize) -> Vec<&Bookmark> {
        let mut bookmarks: Vec<_> = self.bookmarks
            .values()
            .filter(|b| !b.is_private)
            .collect();

        bookmarks.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        bookmarks.into_iter().take(limit).collect()
    }

    /// Get most accessed bookmarks
    pub fn get_most_accessed_bookmarks(&self, limit: usize) -> Vec<&Bookmark> {
        let mut bookmarks: Vec<_> = self.bookmarks
            .values()
            .filter(|b| !b.is_private && b.access_count > 0)
            .collect();

        bookmarks.sort_by(|a, b| b.access_count.cmp(&a.access_count));
        bookmarks.into_iter().take(limit).collect()
    }

    /// Get popular tags
    pub fn get_popular_tags(&self, limit: usize) -> Vec<(String, usize)> {
        self.popular_tags
            .iter()
            .rev()
            .take(limit)
            .map(|(tag, count)| (tag.clone(), *count))
            .collect()
    }

    /// Get bookmarks with specific tag
    pub fn get_bookmarks_with_tag(&self, tag: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .filter(|b| !b.is_private && b.has_tag(tag))
            .collect()
    }

    /// Mark bookmark as accessed
    pub fn mark_accessed(&mut self, id: Uuid) -> Result<(), BookmarkError> {
        let bookmark = self.bookmarks.get_mut(&id).ok_or(BookmarkError::NotFound)?;
        bookmark.mark_accessed();
        Ok(())
    }

    /// Import bookmarks from other browser (placeholder for future implementation)
    pub fn import_bookmarks(&mut self, _data: &str) -> Result<usize, BookmarkError> {
        // TODO: Implement import from HTML, JSON, or other formats
        log::warn!("Bookmark import not yet implemented");
        Ok(0)
    }

    /// Export bookmarks (placeholder for future implementation)
    pub fn export_bookmarks(&self, _format: ExportFormat) -> Result<String, BookmarkError> {
        // TODO: Implement export to HTML, JSON, or other formats
        log::warn!("Bookmark export not yet implemented");
        Ok(String::new())
    }

    /// Get statistics
    pub fn get_stats(&self) -> BookmarkStats {
        let total_bookmarks = self.bookmarks.len();
        let public_bookmarks = self.bookmarks.values().filter(|b| !b.is_private).count();
        let private_bookmarks = total_bookmarks - public_bookmarks;
        let total_folders = self.folders.len();
        let total_tags = self.popular_tags.len();

        BookmarkStats {
            total_bookmarks,
            public_bookmarks,
            private_bookmarks,
            total_folders,
            total_tags,
        }
    }

    /// Update settings
    pub fn update_settings(&mut self, settings: BookmarkSettings) {
        self.settings = settings;
    }

    /// Get settings
    pub fn get_settings(&self) -> &BookmarkSettings {
        &self.settings
    }
}

/// Bookmark update data
#[derive(Debug, Clone)]
pub struct BookmarkUpdate {
    pub title: Option<String>,
    pub url: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub folder_id: Option<Uuid>,
}

/// Bookmark errors
#[derive(Debug, Clone)]
pub enum BookmarkError {
    NotFound,
    AlreadyBookmarked,
    FolderNotFound,
    FolderFull,
    InvalidUrl,
    InvalidFolder,
}

impl std::fmt::Display for BookmarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BookmarkError::NotFound => write!(f, "Bookmark not found"),
            BookmarkError::AlreadyBookmarked => write!(f, "URL already bookmarked"),
            BookmarkError::FolderNotFound => write!(f, "Folder not found"),
            BookmarkError::FolderFull => write!(f, "Folder is full"),
            BookmarkError::InvalidUrl => write!(f, "Invalid URL"),
            BookmarkError::InvalidFolder => write!(f, "Invalid folder"),
        }
    }
}

impl std::error::Error for BookmarkError {}

/// Export formats
#[derive(Debug, Clone)]
pub enum ExportFormat {
    Html,
    Json,
    Csv,
}

/// Bookmark statistics
#[derive(Debug, Clone)]
pub struct BookmarkStats {
    pub total_bookmarks: usize,
    pub public_bookmarks: usize,
    pub private_bookmarks: usize,
    pub total_folders: usize,
    pub total_tags: usize,
}