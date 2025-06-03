#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use citadel_tabs::{
    persistence::ContainerStore,
    TabState, TabType,
};
use uuid::Uuid;
use std::path::PathBuf;
use tempfile::TempDir;
use chrono::{DateTime, Utc};

#[derive(Debug, Arbitrary)]
struct PersistenceInput {
    // Fuzz different operations
    operations: Vec<Operation>,
    // Fuzz different tab states
    states: Vec<TabStateInput>,
}

#[derive(Debug, Arbitrary)]
struct TabStateInput {
    title: String,
    url: String,
    is_active: bool,
}

#[derive(Debug, Arbitrary)]
enum Operation {
    CreateContainer,
    SaveState {
        container_idx: usize,
        state_idx: usize,
    },
    LoadState {
        container_idx: usize,
    },
    DeleteState {
        container_idx: usize,
    },
}

fuzz_target!(|input: PersistenceInput| {
    // Create temporary directory for testing
    if let Ok(temp_dir) = TempDir::new() {
        if let Ok(store) = ContainerStore::new(temp_dir.path().to_path_buf()) {
            // Track created containers and their states
            let mut containers = Vec::new();
            let mut container_states = std::collections::HashMap::new();
            
            // Process each operation
            for op in input.operations {
                match op {
                    Operation::CreateContainer => {
                        let container_id = Uuid::new_v4();
                        if store.create_container(container_id).is_ok() {
                            containers.push(container_id);
                        }
                    },
                    Operation::SaveState { container_idx, state_idx } => {
                        if let Some(&container_id) = containers.get(container_idx % containers.len().max(1)) {
                            if let Some(state_input) = input.states.get(state_idx % input.states.len().max(1)) {
                                let state = TabState {
                                    id: Uuid::new_v4(),
                                    title: state_input.title.clone(),
                                    url: state_input.url.clone(),
                                    tab_type: TabType::Container { container_id },
                                    is_active: state_input.is_active,
                                    created_at: Utc::now(),
                                };
                                
                                if store.save_state(container_id, &state).is_ok() {
                                    container_states.insert(container_id, state);
                                }
                            }
                        }
                    },
                    Operation::LoadState { container_idx } => {
                        if let Some(&container_id) = containers.get(container_idx % containers.len().max(1)) {
                            if let Ok(loaded_state) = store.load_state(container_id) {
                                // Verify loaded state matches saved state
                                if let Some(saved_state) = container_states.get(&container_id) {
                                    assert_eq!(loaded_state.id, saved_state.id);
                                    assert_eq!(loaded_state.title, saved_state.title);
                                    assert_eq!(loaded_state.url, saved_state.url);
                                }
                            }
                        }
                    },
                    Operation::DeleteState { container_idx } => {
                        if let Some(&container_id) = containers.get(container_idx % containers.len().max(1)) {
                            if store.delete_state(container_id).is_ok() {
                                container_states.remove(&container_id);
                                // Verify state is actually deleted
                                assert!(store.load_state(container_id).is_err());
                            }
                        }
                    },
                }
            }
        }
    }
}); 