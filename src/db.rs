use sqlx::{Pool, Sqlite};

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
            filepath TEXT NOT NULL,
            thumbnail TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )"
    )
    .execute(pool)
    .await?;

    Ok(())
}
