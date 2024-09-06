use actix_web::{web, App, HttpServer, HttpResponse, Responder, post};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use bcrypt::{hash, verify, DEFAULT_COST};
use crate::jwt::{create_jwt, verify_jwt};
use crate::models::{initialize_db, create_user, get_user_by_username, update_user_space, User};
use sqlx::sqlite::SqlitePool;

#[derive(Deserialize)]
struct UserLogin {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    allocated_space: usize, // Space in MB
}


#[derive(Deserialize)]
struct FileUpload {
    filename: String,
    size: usize, // File size in MB
}


#[derive(Serialize, Deserialize, Clone)]
pub struct File {
    id: String,
    name: String,
    content: String,
}

#[derive(Clone)]
pub struct AppState {
    files: Arc<Mutex<Vec<File>>>,
}


impl AppState {
    pub fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(Vec::new()))
        }
    }
}

#[post("/register")]
async fn register(
    user_data: web::Json<RegisterRequest>,
    pool: web::Data<SqlitePool>
) -> impl Responder {
    let password_hash = hash(&user_data.password, DEFAULT_COST).unwrap();

    let new_user = User {
        id: Uuid::new_v4().to_string(),
        username: user_data.username.clone(),
        password_hash,
        allocated_space: user_data.allocated_space,
        used_space: 0,
    };

    match create_user(pool.get_ref(), &new_user).await {
        Ok(_) => HttpResponse::Ok().json("User registered"),
        Err(_) => HttpResponse::BadRequest().json("User already exists"),
    }
}

#[post("/login")]
async fn login(credentials: web::Json<UserLogin>, pool: web::Data<SqlitePool>) -> impl Responder {
    match get_user_by_username(&pool, &credentials.username).aw {
        Ok(user) => {
            if verify(&credentials.password, &user.password_hash).unwrap() {
                let token = create_jwt(user.id, 3600).unwrap();
                HttpResponse::Ok().json(token)
            } else {
                HttpResponse::Unauthorized().body("Invalid password")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("Invalid username"),
    }
}

#[post("/upload")]
async fn upload_file(token: web::Header<String>, file: web::Json<FileUpload>, pool: web::Data<SqlitePool>) -> impl Responder {
    let claims = verify_jwt(token.as_str());
    if let Ok(claims) = claims {
        let user_id = claims.sub;
        let user = get_user_by_username(&pool, &user_id).await.unwrap();

        if user.allocated_space >= user.used_space + file.size {
            let new_used_space = user.used_space + file.size;
            update_user_space(&pool, &user.id, new_used_space).await.unwrap();
            HttpResponse::Ok().json("File uploaded successfully")
        } else {
            HttpResponse::BadRequest().json("Not enough space allocated")
        }
    } else {
        HttpResponse::Unauthorized().body("Invalid token")
    }
}

pub async fn get_files(data: web::Data<AppState>) -> impl Responder {
    let files = data.files.lock().unwrap();
    HttpResponse::Ok().json(files.clone())
}

pub async fn get_file_by_id(data: web::Data<AppState>, id: web::Path<String>) -> impl Responder {
    let files = data.files.lock().unwrap();
    if let Some(file) = files.iter().find(|f| f.id == *id) {
        HttpResponse::Ok().json(file)
    } else {
        HttpResponse::NotFound().body("File not found")
    }
}

pub async fn create_file(data: web::Data<AppState>, file: web::Json<File>) -> impl Responder {
    let mut files = data.files.lock().unwrap();
    let mut new_file = file.into_inner();
    new_file.id = Uuid::new_v4().to_string();
    files.push(new_file.clone());
    HttpResponse::Created().json(new_file)
}

pub async fn update_file(
    data: web::Data<AppState>,
    id: web::Path<String>,
    updated_file: web::Json<File>,
) -> impl Responder {
    let mut files = data.files.lock().unwrap();
    if let Some(file) = files.iter_mut().find(|f| f.id == *id) {
        file.name = updated_file.name.clone();
        file.content = updated_file.content.clone();
        HttpResponse::Ok().json(file.clone())
    } else {
        HttpResponse::NotFound().body("File not found")
    }
}

pub async fn delete_file(data: web::Data<AppState>, id: web::Path<String>) -> impl Responder {
    let mut files = data.files.lock().unwrap();
    if let Some(pos) = files.iter().position(|f| f.id == *id) {
        files.remove(pos);
        HttpResponse::Ok().body("File deleted")
    } else {
        HttpResponse::NotFound().body("File not found")
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use serde_json::json;

    #[actix_web::test]
    async fn it_creates_file() {
        let app_state = AppState {
            files: Arc::new(Mutex::new(Vec::new())),
        };

        let mut app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state.clone()))
                .route("/files", web::post().to(create_file)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/files")
            .set_json(&json!({
                "id": "",
                "name": "test.txt",
                "content": "Test content"
            }))
            .to_request();

        let resp: File = test::call_and_read_body_json(&mut app, req).await;
        assert_eq!(resp.name, "test.txt");
        assert_eq!(resp.content, "Test content");
    }

    #[actix_web::test]
    async fn it_gets_files() {
        let app_state = AppState {
            files: Arc::new(Mutex::new(vec![File {
                id: "1".to_string(),
                name: "test.txt".to_string(),
                content: "Test content".to_string(),
            }])),
        };

        let mut app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state.clone()))
                .route("/files", web::get().to(get_files)),
        )
        .await;

        let req = test::TestRequest::get().uri("/files").to_request();

        let resp: Vec<File> = test::call_and_read_body_json(&mut app, req).await;
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].name, "test.txt");
    }

    #[actix_web::test]
    async fn it_deletes_file() {
        let app_state = AppState {
            files: Arc::new(Mutex::new(vec![File {
                id: "1".to_string(),
                name: "test.txt".to_string(),
                content: "Test content".to_string(),
            }])),
        };

        let mut app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state.clone()))
                .route("/files/{id}", web::delete().to(delete_file)),
        )
        .await;

        let req = test::TestRequest::delete().uri("/files/1").to_request();
        let resp = test::call_and_read_body(&mut app, req).await;

        assert_eq!(resp, "File deleted");
    }
}

