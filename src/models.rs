use sqlx::{sqlite::SqlitePoolOptions, Pool, Row, Sqlite};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub allocated_space: usize, // in MB
    pub used_space: usize, // in MB
}

pub async fn initialize_db(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            allocated_space INTEGER,
            used_space INTEGER
        )"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            filename TEXT NOT NULL,
            size INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )"
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn create_user(pool: &Pool<Sqlite>, user: &User) -> Result<(), sqlx::Error> {
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

pub async fn get_user_by_username(pool: &Pool<Sqlite>, username: &str) -> Result<User, sqlx::Error> {
    let query = "SELECT id, username, password_hash, allocated_space, used_space FROM users WHERE username = ?";

    // Execute the query and get a single row
    let row = sqlx::query(query)
        .bind(username) // Bind the parameter
        .fetch_one(pool) // Fetch a single row
        .await?;

    // Extract the fields from the row and map them to the User struct
    let user = User {
        id: row.get("id"),
        username: row.get("username"),
        password_hash: row.get("password_hash"),
        allocated_space: row.get::<i32, _>("allocated_space") as usize,
        used_space: row.get::<i32, _>("used_space") as usize,
    };

    Ok(user)
}

pub async fn update_user_space(pool: &Pool<Sqlite>, user_id: &str, used_space: usize) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE users SET used_space = ? WHERE id = ?"
    )
    .bind(used_space as i64)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}
