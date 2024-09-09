use sqlx::{Row, sqlite::SqlitePool};
use crate::model::User;
use anyhow::Result;

pub struct UserRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> UserRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create_user(&self, user: &User) -> Result<()> {
        sqlx::query("INSERT INTO users (id, username, password_hash, allocated_space, used_space) VALUES (?, ?, ?, ?, ?)")
            .bind(&user.id)
            .bind(&user.username)
            .bind(&user.password_hash)
            .bind(user.allocated_space as i64)
            .bind(user.used_space as i64)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User> {
        let row = sqlx::query("SELECT id, username, password_hash, allocated_space, used_space FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(self.pool)
            .await?;

        let user = User {
            id: row.get("id"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            allocated_space: row.get("allocated_space"),
            used_space: row.get("used_space"),
        };
        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<User> {
        let row = sqlx::query("SELECT id, username, password_hash, allocated_space, used_space FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(self.pool)
            .await?;

        let user = User {
            id: row.get("id"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            allocated_space: row.get("allocated_space"),
            used_space: row.get("used_space"),
        };
        Ok(user)
    }

    pub async fn update_user_space(&self, user_id: &str, new_used_space: u64) -> Result<()> {
        sqlx::query("UPDATE users SET used_space = ? WHERE id = ?")
            .bind(new_used_space as i64)
            .bind(user_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }
}