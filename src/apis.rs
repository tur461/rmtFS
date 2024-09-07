use actix_web::{web, HttpRequest, HttpResponse, Responder};
use futures::Stream;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use actix_multipart::Multipart;

use bcrypt::{hash, verify, DEFAULT_COST};
use crate::jwt::create_jwt;
use crate::models::{
    User,
    create_user, 
    get_user_by_id, 
    update_user_space, 
    get_user_by_username, 
};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::fs;
use log::error;
use std::io::Write;
use actix_files::NamedFile;
use crate::constants::PATH_TO_FILES;
use base64::{encode as base64_encode};
use crate::utils::{detect_file_type, get_thumb_path};
use futures_util::TryStreamExt as _;

#[derive(Deserialize)]
pub struct UserLogin {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    username: String,
    password: String,
    allocated_space: usize, // Space in MB
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct File {
    pub id: String,
    pub user_id: String,
    pub filename: String,
    pub filepath: String,
    pub size: usize,
    thumbnail: Option<String>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileReq {
    pub filename: String,
    pub content: String,
    // optional
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub filepath: String,
    #[serde(default)]
    pub size: usize,
}

pub async fn register(
    user_data: web::Json<RegisterRequest>,
    pool: web::Data<SqlitePool>
) -> impl Responder {
    log::info!("called");
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

pub async fn login(
    creds: web::Json<UserLogin>, 
    pool: web::Data<SqlitePool>,
    secret: web::Data<String>
) -> impl Responder {
    match get_user_by_username(&pool, &creds.username).await {
        Ok(user) => {
            if verify(&creds.password, &user.password_hash).unwrap() {
                let token = create_jwt(user.id, &secret).unwrap();
                HttpResponse::Ok().json(token)
            } else {
                HttpResponse::Unauthorized().body("Invalid password")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("Invalid username"),
    }
}

pub async fn get_user_details( 
    pool: web::Data<SqlitePool>,
    user_id: web::Path<String>
) -> impl Responder {
    let user = get_user_by_id(&pool, &user_id).await;
    if user.is_err() {
        return HttpResponse::InternalServerError().body("user not found!.");
    }
    let user = user.unwrap();
    
    HttpResponse::Ok().json(user)
}


pub async fn get_files(
    pool: web::Data<SqlitePool>,
    user_id: web::Path<String>
) -> impl Responder {
    let rows = sqlx::query("SELECT id, user_id, filename, filepath, size, thumbnail FROM files WHERE user_id = ?")
        .bind(user_id.to_string())
        .fetch_all(pool.get_ref())
        .await;

    match rows {
        Ok(files) => {
            let files: Vec<File> = files.into_iter().map(|row| {
                let id: String = row.try_get("id").unwrap();
                let user_id: String = row.try_get("user_id").unwrap();
                let filename: String = row.try_get("filename").unwrap();
                let filepath: String = row.try_get("filepath").unwrap();
                let size: usize = row.get::<i32, _>("size") as usize;
                let thumb_path: String = row.try_get("thumbnail").unwrap();

                let thumb_data = if std::path::Path::new(&thumb_path).exists() {
                    match fs::read(&thumb_path) {
                        Ok(data) => Some(base64_encode(data)),
                        Err(_) => None,
                    }
                } else {
                    None
                };

                File {
                    id,
                    user_id,
                    filename,
                    filepath,
                    size,
                    thumbnail: thumb_data,
                }
            }).collect();

            HttpResponse::Ok().json(files)
        },
        Err(e) => {
            error!("Error Fetching Files: {}", e);
            HttpResponse::InternalServerError().body("Error fetching files")
        },
    }
}

pub async fn get_file_by_id(
    pool: web::Data<SqlitePool>, 
    file_id: web::Path<String>,
    req: HttpRequest
) -> impl Responder {
    let f_res = sqlx::query("SELECT id, filename, filepath, size FROM files WHERE id = ?")
        .bind(file_id.into_inner())
        .fetch_optional(pool.get_ref())
        .await;

        match f_res {
            Ok(Some(file)) => {
                let filepath: String = file.try_get("filepath").unwrap();
                let filename: String = file.try_get("filename").unwrap();
                
                if !std::path::Path::new(&filepath).exists() {
                    return HttpResponse::NotFound().body("File not found on disk");
                }

                log::info!("## Reading file: {}", filepath);
                
                match NamedFile::open(filepath) {
                    Ok(named_file) => {
                        named_file
                            .use_last_modified(true)
                            .set_content_disposition(
                                actix_web::http::header::ContentDisposition {
                                    disposition: actix_web::http::header::DispositionType::Attachment,
                                    parameters: vec![
                                        actix_web::http::header::DispositionParam::Filename(filename)
                                    ]
                                }
                            )
                            .into_response(&req)
                    }
                    Err(_) => HttpResponse::InternalServerError().body("Error opening file"),
                }
            }
            Ok(None) => HttpResponse::NotFound().body("File not found"),
            Err(_) => HttpResponse::InternalServerError().body("Error fetching the file"),
        }
}


pub async fn create_file(
    pool: web::Data<SqlitePool>, 
    mut payload: Multipart, 
    user_id: web::Path<String>
) -> impl Responder {
    let user = get_user_by_id(&pool, &user_id).await;
    if user.is_err() {
        return HttpResponse::InternalServerError().body("User not found.");
    }
    let user = user.unwrap();
    let (allocated_space, used_space) = (user.allocated_space, user.used_space);

    let mut filepath = String::new();
    let mut filename = String::new();
    let mut file_size: usize = 0;

    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition().unwrap();
        filename = content_disposition.get_filename().unwrap().to_string();
        let file_id = Uuid::new_v4().to_string();
        log::info!("## GOT a file: {}", filename);

        let user_dir = format!("{}/{}", PATH_TO_FILES, user_id);
        if !std::path::Path::new(&user_dir).exists() {
            fs::create_dir_all(&user_dir).unwrap();
        }

        filepath = format!("{}/{}", user_dir, filename);
        let fp = filepath.clone();
        let mut f = web::block(move || std::fs::File::create(&fp)).await.unwrap().unwrap();
        log::info!("## Field: {} {:?} {}", field.size_hint().0, field.size_hint().1, field.name().unwrap());

        while let Some(chunk) = field.try_next().await.unwrap() {
            log::info!("## Chunk: {:?}", chunk.len());
            file_size += chunk.len();
            f = web::block(move || f.write_all(&chunk).map(|_| f)).await.unwrap().unwrap();
        }


    }

    if used_space + file_size > allocated_space {
        fs::remove_file(filepath).unwrap(); // rm file if space is insufficient
        return HttpResponse::BadRequest().body("File too big: out of space");
    }

    let file_type = detect_file_type(&filepath);
    let thumb_path = get_thumb_path(file_type);

    let result = sqlx::query("INSERT INTO files (id, user_id, filename, filepath, size, thumbnail) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&Uuid::new_v4().to_string())
        .bind(user_id.to_string())
        .bind(&filename)
        .bind(&filepath)
        .bind(file_size.to_string())
        .bind(thumb_path)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => {
            let new_used_space = used_space + file_size;
            if let Err(_) = update_user_space(pool.get_ref(), &user_id, new_used_space).await {
                return HttpResponse::InternalServerError().body("Error updating user space");
            }

            HttpResponse::Created().json("File uploaded successfully")
        }
        Err(_) => {
            fs::remove_file(filepath).unwrap(); // rm file if DB insertion fails
            HttpResponse::InternalServerError().body("Error saving file metadata")
        }
    }
}

pub async fn update_file(
    pool: web::Data<SqlitePool>, 
    id: web::Path<String>, 
    updated_file: web::Json<File>
) -> impl Responder {
    let file_id = id.into_inner();
    let filepath = format!("/path/to/files/{}", updated_file.filename);  // Adjust path

    match fs::write(&filepath, "new file content") {  // Replace with actual new content
        Ok(_) => (),
        Err(_) => return HttpResponse::InternalServerError().body("Error updating file on disk"),
    }

    let result = sqlx::query("UPDATE files SET filename = ?, filepath = ?, size = ? WHERE id = ?")
        .bind(&updated_file.filename)
        .bind(&filepath)
        .bind(updated_file.size.to_string())
        .bind(file_id)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().json("File updated successfully"),
        Err(_) => HttpResponse::InternalServerError().body("Error updating file metadata"),
    }
}

pub async fn delete_file(
    pool: web::Data<SqlitePool>, 
    f_u_id: web::Path<String>,
) -> impl Responder {
    let fuid = f_u_id.into_inner();
    log::info!("## Deleting file: {}", fuid);
    let splits = fuid.split("__").collect::<Vec<&str>>();
    if splits.len() != 2 {
        return HttpResponse::InternalServerError().body("Invalid ID compound!.");
    }
    let user_id = splits.get(0).unwrap();
    let file_id = splits.get(1).unwrap();
    
    let user = get_user_by_id(&pool, &user_id).await;
    if user.is_err() {
        return HttpResponse::InternalServerError().body("user not found!.");
    }
    let user = user.unwrap();
    

    let file_row = sqlx::query("SELECT filepath, size FROM files WHERE id = ?")
        .bind(&file_id)
        .fetch_optional(pool.get_ref())
        .await;

    match file_row {
        Ok(Some(file)) => {
            let filepath: String = file.try_get("filepath").unwrap();
            let file_size: usize = file.get::<i32, _>("size") as usize;

            if let Err(_) = fs::remove_file(&filepath) {
                return HttpResponse::InternalServerError().body("Error deleting file from disk");
            }

            let result = sqlx::query("DELETE FROM files WHERE id = ?")
                .bind(&file_id)
                .execute(pool.get_ref())
                .await;

            match result {
                Ok(_) => {
                    let used_space = user.used_space;
                    let new_used_space = used_space - file_size;
                    if let Err(_) = update_user_space(pool.get_ref(), &user_id, new_used_space).await {
                        return HttpResponse::InternalServerError().body("Error updating user space");
                    }

                    HttpResponse::Ok().body("File deleted successfully")
                }
                Err(_) => HttpResponse::InternalServerError().body("Error deleting file metadata"),
            }
        }
        Ok(None) => HttpResponse::NotFound().body("File not found"),
        Err(_) => HttpResponse::InternalServerError().body("Error fetching file"),
    }
}