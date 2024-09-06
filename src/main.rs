mod apis;

mod jwt;
mod models;

use std::sync::{Arc, Mutex};
use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use apis::{
    AppState, 
    login, 
    register, 
    get_files, 
    get_file_by_id, 
    create_file, 
    update_file, 
    delete_file
};

use sqlx::sqlite::SqlitePool;
use models::initialize_db;
use dotenv::dotenv;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    
    let app_state = AppState::new(); 
    let pool = SqlitePool::connect("sqlite:db.sqlite").await.unwrap();
    initialize_db(&pool);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/login", web::get().to(login))
            .route("/register", web::get().to(register))
            .route("/files", web::get().to(get_files))
            .route("/files/{id}", web::get().to(get_file_by_id))
            .route("/files", web::post().to(create_file))
            .route("/files/{id}", web::put().to(update_file))
            .route("/files/{id}", web::delete().to(delete_file))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

