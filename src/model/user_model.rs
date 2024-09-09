use sqlx::{Pool, Row, Sqlite};
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
    pub allocated_space: u64, // in MB
    pub used_space: u64, // in MB
}

impl User {
    pub async fn create_user(pool: &Pool<Sqlite>, user: &Self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, allocated_space, used_space) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.allocated_space as i64)
        .bind(user.used_space as i64)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn get_by_id(pool: &Pool<Sqlite>, id: &str) -> Result<User, sqlx::Error> {
        let query = "SELECT id, username, password_hash, allocated_space, used_space FROM users WHERE id = ?";

        let row = sqlx::query(query)
            .bind(id)
            .fetch_one(pool)
            .await?;

        Ok(User {
            id: row.get("id"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            allocated_space: row.get::<u64, _>("allocated_space") as u64,
            used_space: row.get::<u64, _>("used_space") as u64,
        })
    }

    pub async fn get_by_username(pool: &Pool<Sqlite>, username: &str) -> Result<User, sqlx::Error> {
        let query = "SELECT id, username, password_hash, allocated_space, used_space FROM users WHERE username = ?";

        let row = sqlx::query(query)
            .bind(username)
            .fetch_one(pool)
            .await?;

        Ok(User {
            id: row.get("id"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            allocated_space: row.get::<u64, _>("allocated_space") as u64,
            used_space: row.get::<u64, _>("used_space") as u64,
        })
    }

    pub async fn update_space(pool: &Pool<Sqlite>, user_id: &str, used_space: u64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE users SET used_space = ? WHERE id = ?"
        )
        .bind(used_space as i64)
        .bind(user_id)
        .execute(pool)
        .await?;
        Ok(())
    }
}
