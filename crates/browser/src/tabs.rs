use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use url::Url;
use uuid::Uuid;

/// Represents the state of a browser tab
#[derive(Debug)]
pub struct Tab {
    /// Unique identifier for the tab
    id: Uuid,
    /// Current URL of the tab
    url: RwLock<Url>,
    /// Tab title
    title: RwLock<String>,
    /// Whether the tab is currently loading
    is_loading: Mutex<bool>,
}

impl Tab {
    /// Create a new tab with the given URL
    pub fn new(url: Url) -> Self {
        Self {
            id: Uuid::new_v4(),
            url: RwLock::new(url),
            title: RwLock::new(String::new()),
            is_loading: Mutex::new(false),
        }
    }

    /// Get the tab's ID
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Get the current URL
    pub fn url(&self) -> Url {
        self.url.read().unwrap().clone()
    }

    /// Set a new URL for the tab
    pub fn set_url(&self, url: Url) {
        *self.url.write().unwrap() = url;
    }

    /// Get the tab's title
    pub fn title(&self) -> String {
        self.title.read().unwrap().clone()
    }

    /// Set the tab's title
    pub fn set_title(&self, title: String) {
        *self.title.write().unwrap() = title;
    }

    /// Check if the tab is currently loading
    pub fn is_loading(&self) -> bool {
        *self.is_loading.lock().unwrap()
    }

    /// Set the loading state
    pub fn set_loading(&self, loading: bool) {
        *self.is_loading.lock().unwrap() = loading;
    }
}

/// Manages all browser tabs
#[derive(Debug)]
pub struct TabManager {
    /// All open tabs
    tabs: RwLock<HashMap<Uuid, Arc<Tab>>>,
    /// Currently active tab ID
    active_tab: RwLock<Option<Uuid>>,
}

impl TabManager {
    /// Create a new tab manager
    pub fn new() -> Self {
        Self {
            tabs: RwLock::new(HashMap::new()),
            active_tab: RwLock::new(None),
        }
    }

    /// Create a new tab and return its ID
    pub fn create_tab(&self, url: Url) -> Uuid {
        let tab = Arc::new(Tab::new(url));
        let id = tab.id();
        
        let mut tabs = self.tabs.write().unwrap();
        tabs.insert(id, tab);
        
        // If this is the first tab, make it active
        if tabs.len() == 1 {
            *self.active_tab.write().unwrap() = Some(id);
        }
        
        id
    }

    /// Close a tab by ID
    pub fn close_tab(&self, id: Uuid) -> bool {
        let mut tabs = self.tabs.write().unwrap();
        let mut active_tab = self.active_tab.write().unwrap();
        
        if let Some(removed_tab) = tabs.remove(&id) {
            // If we closed the active tab, activate the next available tab
            if active_tab.map_or(false, |active_id| active_id == id) {
                *active_tab = tabs.keys().next().copied();
            }
            true
        } else {
            false
        }
    }

    /// Get a reference to a tab by ID
    pub fn get_tab(&self, id: Uuid) -> Option<Arc<Tab>> {
        self.tabs.read().unwrap().get(&id).cloned()
    }

    /// Get the active tab
    pub fn active_tab(&self) -> Option<Arc<Tab>> {
        let active_id = *self.active_tab.read().unwrap();
        active_id.and_then(|id| self.get_tab(id))
    }

    /// Set the active tab
    pub fn set_active_tab(&self, id: Uuid) -> bool {
        if self.tabs.read().unwrap().contains_key(&id) {
            *self.active_tab.write().unwrap() = Some(id);
            true
        } else {
            false
        }
    }

    /// Get all open tabs
    pub fn all_tabs(&self) -> Vec<Arc<Tab>> {
        self.tabs.read().unwrap().values().cloned().collect()
    }

    /// Get the number of open tabs
    pub fn tab_count(&self) -> usize {
        self.tabs.read().unwrap().len()
    }
}

impl Default for TabManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tab_creation() {
        let manager = TabManager::new();
        let url = Url::parse("https://example.com").unwrap();
        let id = manager.create_tab(url.clone());
        
        let tab = manager.get_tab(id).unwrap();
        assert_eq!(tab.url(), url);
        assert_eq!(manager.tab_count(), 1);
        assert_eq!(manager.active_tab().unwrap().id(), id);
    }

    #[test]
    fn test_tab_closing() {
        let manager = TabManager::new();
        let url1 = Url::parse("https://example1.com").unwrap();
        let url2 = Url::parse("https://example2.com").unwrap();
        
        let id1 = manager.create_tab(url1);
        let id2 = manager.create_tab(url2);
        
        assert_eq!(manager.tab_count(), 2);
        assert!(manager.close_tab(id1));
        assert_eq!(manager.tab_count(), 1);
        assert_eq!(manager.active_tab().unwrap().id(), id2);
    }

    #[test]
    fn test_tab_switching() {
        let manager = TabManager::new();
        let url1 = Url::parse("https://example1.com").unwrap();
        let url2 = Url::parse("https://example2.com").unwrap();
        
        let id1 = manager.create_tab(url1);
        let id2 = manager.create_tab(url2);
        
        assert_eq!(manager.active_tab().unwrap().id(), id1);
        assert!(manager.set_active_tab(id2));
        assert_eq!(manager.active_tab().unwrap().id(), id2);
    }
} 