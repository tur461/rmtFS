mod db;
mod jwt;
mod repo;
mod utils;
mod model;
mod handler;
mod constants;

// #[cfg(test)]
// mod apis_mock;

use std::env;
use dotenv::dotenv;
use env_logger::Env;
use actix_cors::Cors;
use db::initialize_db;
use jwt::Authentication;
use sqlx::sqlite::SqlitePoolOptions;
use handler::{FileHandler, UserHandler};
use actix_web::{http::header, web::{self, head}, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let jwt_secret = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/secret.key"));
    let sqlite_db_file = env::var("SQLITE_DB_URL").expect("SQLITE_DB_URL");
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&sqlite_db_file)
        .await
        .expect("create pool");
    
    if let Err(e) = initialize_db(&pool).await {
        panic!("Unable to initialize the db. Err: {:?}", e);
    }
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(jwt_secret.to_string())) 
            .wrap(Authentication)
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .expose_headers(vec![
                        header::CONTENT_DISPOSITION, 
                        header::HeaderName::from_static("x-file-iv")
                    ])
                    .supports_credentials()
                    .max_age(3600),
            )
            .wrap(actix_web::middleware::Logger::default())
            .route("/login", web::post().to(UserHandler::login))
            .route("/register", web::post().to(UserHandler::register))
            .route("/user/{id}", web::get().to(UserHandler::get_user_details))
            .route("/files/get_all_by_uid/{id}", web::get().to(FileHandler::get_files))
            .route("/files/get_one_by_fid/{id}", web::get().to(FileHandler::get_file_by_id))
            .route("/files/cre_by_uid/{id}", web::post().to(FileHandler::create_file))
            .route("/files/del_by_fid/{id}", web::delete().to(FileHandler::delete_file))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

