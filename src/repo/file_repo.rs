use sqlx::{Row, sqlite::SqlitePool};
use crate::model::File;
use anyhow::Result;
use std::fs;
use base64::{encode as base64_encode};
use futures_util::TryStreamExt as _;
use futures::Stream;

pub struct FileRepo<'a> {
    pool: &'a SqlitePool,
}

impl<'a> FileRepo<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get_files_by_user_id(&self, user_id: &str) -> Result<Vec<File>> {
        let rows = sqlx::query("SELECT id, user_id, filename, filepath, size, thumbnail FROM files WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(self.pool)
            .await?;

        let files: Vec<File> = rows
            .into_iter()
            .map(|row| {
                let id: String = row.try_get("id").unwrap();
                let user_id: String = row.try_get("user_id").unwrap();
                let filename: String = row.try_get("filename").unwrap();
                let filepath: String = row.try_get("filepath").unwrap();
                let size: u64 = row.get::<u64, _>("size") as u64;
                let thumb_path: String = row.try_get("thumbnail").unwrap();
                let thumbnail = if std::path::Path::new(&thumb_path).exists() {
                    match fs::read(&thumb_path) {
                        Ok(data) => base64_encode(data),
                        Err(_) => String::from(""),
                    }
                } else {
                    String::from("")
                };
                File {
                    id, user_id, filename, filepath, size, thumbnail
                }
            })
            .collect();

        Ok(files)
    }

    pub async fn get_file_by_id(&self, file_id: &str) -> Result<File, anyhow::Error> {
        let row = sqlx::query("SELECT id, user_id, filename, filepath, size, thumbnail FROM files WHERE id = ?")
        .bind(file_id)
        .fetch_optional(self.pool)
        .await?;

        if let Some(row) = row {
            let id: String = row.try_get("id").unwrap();
            let user_id: String = row.try_get("user_id").unwrap();
            let filename: String = row.try_get("filename").unwrap();
            let filepath: String = row.try_get("filepath").unwrap();
            let size: u64 = row.get::<u64, _>("size") as u64;
            let thumb_path: String = row.try_get("thumbnail").unwrap();
    
            let thumbnail = if std::path::Path::new(&thumb_path).exists() {
                match fs::read(&thumb_path) {
                    Ok(data) => base64_encode(data),
                    Err(_) => String::from(""),
                }
            } else {
                String::from("")
            };
    
            let file = File {
                id, user_id, filename, filepath, size, thumbnail
            };
            Ok(file)
        } else {
            anyhow::bail!("File with id {} not found.", file_id)
        }

    }

    pub async fn create_file(&self, file: &File) -> Result<()> {
        sqlx::query("INSERT INTO files (id, user_id, filename, filepath, size, thumbnail) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(&file.id)
            .bind(&file.user_id)
            .bind(&file.filename)
            .bind(&file.filepath)
            .bind(file.size as i64)
            .bind(file.thumbnail.clone())
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_file(&self, file_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM files WHERE id = ?")
            .bind(file_id)
            .execute(self.pool)
            .await?;
        Ok(())
    }
}
