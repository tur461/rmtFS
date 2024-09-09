use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct UserLogin {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub allocated_space: u64, // Space in Bytes
}


#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub allocated_space: u64, // in bytes
    pub used_space: u64, // in bytes
}