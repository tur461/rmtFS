
use actix_web::test::TestRequest;

use actix_web::{test, web, App, HttpRequest};
use sqlx::sqlite::SqlitePool;
use crate::apis::*;
use crate::models::*;
use serde_json::json;

async fn setup_test_db(pool: &SqlitePool) {
    sqlx::query(
        "CREATE TABLE users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            allocated_space INTEGER NOT NULL,
            used_space INTEGER NOT NULL
        )"
    )
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE files (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            size INTEGER NOT NULL,
            thumbnail TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )"
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn setup_test_app() -> (actix_web::App<String>, SqlitePool) {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    setup_test_db(&pool).await;

    let app = App::new()
        .app_data(web::Data::new(pool.clone()))
        .app_data(web::Data::new("secret".to_string())) // replace with actual secret
        .service(
            web::scope("/api")
                .route("/register", web::post().to(register))
                .route("/login", web::post().to(login))
                .route("/user/{id}", web::get().to(get_user_details))
                .route("/files/get_all_by_uid/{id}", web::get().to(get_files))
                .route("/files/get_one_by_fid/{id}", web::get().to(get_file_by_id))
                .route("/files/cre_by_uid/{id}", web::post().to(create_file))
                .route("/files/up_by_fid/{id}", web::put().to(update_file))
                .route("/files/del_by_compid/{id}", web::delete().to(delete_file)),
        );


    (app, pool)
}
