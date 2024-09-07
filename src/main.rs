mod apis;

mod jwt;
mod models;
mod constants;

use std::sync::{Arc, Mutex};
use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use apis::{
    login, 
    register, 
    get_files, 
    create_file, 
    delete_file, 
    update_file,
    get_file_by_id, 
    get_user_details, 
};

use jwt::Authentication;
use actix_cors::Cors;
use actix_web_httpauth::middleware::HttpAuthentication;

use sqlx::sqlite::SqlitePool;
use models::initialize_db;
use dotenv::dotenv;
use std::env;
use env_logger::Env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let jwt_secret = include_str!("..\\secret.key");
    let sqlite_db_file = env::var("SQLITE_DB_URL").expect("SQLITE_DB_URL");

    let pool = SqlitePool::connect(&sqlite_db_file).await.unwrap();
    let r = initialize_db(&pool).await;
    if r.is_err() {
        let error = r.unwrap_err();
        panic!("Unable to initialize the db. Err: {:?}", error);
    }
    HttpServer::new(move || {
        let secret = String::from(jwt_secret);
        // let auth = HttpAuthentication::bearer(move |req, creds| {
        //     log::info!("jwt mid hit");
        //     log::warn!("jwt mid hit");
        //     log::error!("jwt mid hit");
        //     log::debug!("jwt mid hit");
        //     let sec = String::from(&secret);
        //     async move { jwt_validator(req, creds, &sec) }
        // });
        
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(jwt_secret.to_string())) 
            .wrap(Authentication)
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
                    .supports_credentials()
                    .max_age(3600),
            )
            .wrap(actix_web::middleware::Logger::default())
            .route("/login", web::post().to(login))
            .route("/register", web::post().to(register))
            .route("/user/{id}", web::get().to(get_user_details))
            .route("/files/get_all_by_uid/{id}", web::get().to(get_files))
            .route("/files/get_one_by_fid/{id}", web::get().to(get_file_by_id))
            .route("/files/cre_by_uid/{id}", web::post().to(create_file))
            .route("/files/up_by_fid/{id}", web::put().to(update_file))
            .route("/files/del_by_fid/{id}", web::delete().to(delete_file))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

