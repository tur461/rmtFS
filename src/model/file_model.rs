use sqlx::{Pool, Sqlite};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct File {
    pub id: String,
    pub user_id: String,
    pub filename: String,
    pub size: u64, // in bytes
    pub filepath: String,
    pub thumbnail: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileReq {
    pub filename: String,
    pub content: String,
    // optional
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub filepath: String,
    #[serde(default)]
    pub size: u64,
}

// todo: Add file-related functions here
