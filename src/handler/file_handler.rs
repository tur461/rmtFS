use actix_web::{
    web, 
    http::header::{ 
        DispositionType, 
        DispositionParam,
        ContentDisposition,
    }, 
    HttpRequest, 
    HttpResponse, 
    Responder
};
use crate::constants::PATH_TO_FILES;
use crate::repo::{FileRepo, UserRepo};
use crate::model::File;
use crate::utils::{
    add_tstamp, 
    detect_file_type, 
    get_thumb_path, 
    strip_tstamp
};
use sqlx::sqlite::SqlitePool;
use actix_files::NamedFile;
use uuid::Uuid;
use std::fs;
use std::io::Write;
use actix_multipart::Multipart;
use futures_util::TryStreamExt as _;

pub struct FileHandler;

impl FileHandler {

    pub async fn get_files(
        pool: web::Data<SqlitePool>,
        user_id: web::Path<String>
    ) -> impl Responder {
        let file_repo = FileRepo::new(pool.get_ref());

        match file_repo.get_files_by_user_id(&user_id).await {
            Ok(files) => HttpResponse::Ok().json(files),
            Err(_) => HttpResponse::InternalServerError().body("Error fetching files"),
        }
    }

    pub async fn get_file_by_id(
        pool: web::Data<SqlitePool>, 
        file_id: web::Path<String>,
        req: HttpRequest
    ) -> impl Responder {
        let file_repo = FileRepo::new(pool.get_ref());
        match file_repo.get_file_by_id(&file_id).await {
            Ok(file) => {
                let filepath: String = file.filepath;
                let filename: String = strip_tstamp(&file.filename);
                
                if !std::path::Path::new(&filepath).exists() {
                    return HttpResponse::NotFound().body("File not found on disk");
                }

                log::info!("## Reading file: {}", filepath);
                
                match NamedFile::open(filepath) {
                    Ok(named_file) => {
                        let content_disposition = ContentDisposition {
                            disposition: DispositionType::Attachment,
                            parameters: vec![
                                DispositionParam::Filename(filename)
                            ],
                        };
                        let mut response = named_file
                            .use_last_modified(true)
                            .set_content_disposition(content_disposition)
                            .into_response(&req);
                        response.headers_mut().insert(
                            "x-file-iv".parse().unwrap(),
                            file.ivector.parse().unwrap()
                        );
                        
                        response
                        
                    },
                    Err(_) => HttpResponse::InternalServerError().body("Error opening file"),
                }
            },
            Err(_) => HttpResponse::NotFound().json(format!("File with id {}, not found", file_id))
        }

    }

    pub async fn create_file(
        pool: web::Data<SqlitePool>, 
        mut payload: Multipart, 
        user_id: web::Path<String>
    ) -> impl Responder {
        let user_repo = UserRepo::new(pool.get_ref());
        match user_repo.get_user_by_id(&user_id).await {
            Ok(user) => {
                let (allocated_space, used_space) = (user.allocated_space, user.used_space);

                let mut file_size: u64 = 0;
                let mut ivector: String = String::new();
                let mut filepath = String::new();
                let mut filename = String::new();
                while let Ok(Some(mut field)) = payload.try_next().await {
                    let content_disposition = field.content_disposition().unwrap();
                    let field_name = content_disposition.get_name().unwrap();
                    if field_name == "file" {
                        log::info!("Field: FILE");
                        filename = content_disposition.get_filename().unwrap().to_string();
                        log::info!("## GOT a file: {}", filename);
                        filename = add_tstamp(&filename);
                        let user_dir = format!("{}/{}", PATH_TO_FILES, user_id);
                        if !std::path::Path::new(&user_dir).exists() {
                            fs::create_dir_all(&user_dir).unwrap();
                        }

                        

                        filepath = format!("{}/{}", user_dir, filename);
                        let fp = filepath.clone();
                        let mut f = web::block(move || std::fs::File::create(&fp)).await.unwrap().unwrap();

                        while let Some(chunk) = field.try_next().await.unwrap() {
                            log::info!("## Chunk: {:?}", chunk.len());
                            file_size += chunk.len() as u64;
                            f = web::block(move || f.write_all(&chunk).map(|_| f)).await.unwrap().unwrap();
                        }


                    } else if field_name == "ivector" {
                        
                        let v = match field.try_fold(Vec::new(), |mut acc, chunk| {
                            acc.extend_from_slice(&chunk);
                            async move { Ok(acc) } // Return Result
                        }).await {
                            Ok(iv_data) => Some(iv_data),
                            Err(e) => {
                                log::error!("Failed to extract IV: {}", e);
                                return HttpResponse::InternalServerError().finish();
                            }
                        }.unwrap_or_default();
                        
                        ivector = base64::encode(&v);
                        log::info!("IV: {}", ivector);
                    }
                }  

                if used_space + file_size > allocated_space {
                    fs::remove_file(filepath).unwrap(); // rm file if space is insufficient
                    return HttpResponse::BadRequest().body("File too big: out of space");
                }

                let file_type = detect_file_type(&filepath);
                let thumb_path = get_thumb_path(file_type);

                let file_repo = FileRepo::new(pool.get_ref());

                match file_repo.create_file(&File { 
                    filename,
                    ivector,
                    size: file_size, 
                    thumbnail: thumb_path,
                    user_id: user_id.clone(), 
                    filepath: filepath.clone(), 
                    id: Uuid::new_v4().to_string(), 
                }).await {
                    Ok(_) => {
                        let new_used_space = used_space + file_size;
                        if let Err(_) =  user_repo.update_user_space(&user_id, new_used_space).await {
                            return HttpResponse::InternalServerError().body("Error updating user space");
                        }

                        HttpResponse::Created().json("File uploaded successfully")
                    },
                    Err(e) => {
                        log::error!("Saving File: {}", e);
                        fs::remove_file(filepath).unwrap(); // rm file if DB insertion fails
                        HttpResponse::InternalServerError().body("Error saving file metadata")
                    }
                }

            },
            Err(_) => HttpResponse::NotFound().json(format!("User with id {}, not found.", user_id))
        }
    }

    pub async fn delete_file(
        pool: web::Data<SqlitePool>, 
        file_id: web::Path<String>,
    ) -> impl Responder {
        log::info!("## Deleting file: {}", file_id);
        let file_repo = FileRepo::new(pool.get_ref());
        let file_id = file_id.into_inner();
        match file_repo.get_file_by_id(&file_id).await {
            Ok(file) => {
                let filepath: String = file.filepath;
                

                if let Err(_) = fs::remove_file(&filepath) {
                    return HttpResponse::InternalServerError().body("Error deleting file from disk");
                }

                match file_repo.delete_file(&file_id).await {
                    Ok(_) => {
                        let user_id = file.user_id;
                        let user_repo = UserRepo::new(&pool.as_ref());
                        let user = user_repo.get_user_by_id(&user_id).await.expect(&format!("a user with id {}", user_id));

                        let used_space = user.used_space;
                        let file_size: u64 = file.size;
                        let new_used_space = used_space - file_size;
                        if let Err(_) = user_repo.update_user_space(&user_id, new_used_space).await {
                            return HttpResponse::InternalServerError().body("Error updating user space");
                        }

                        HttpResponse::Ok().body("File deleted successfully")
                    },
                    Err(_) => HttpResponse::InternalServerError().body("Error deleting file metadata"),
                }
            },
            Err(_) => HttpResponse::NotFound().json(format!("file with id {}, not found.", file_id)),
        }
    }

}
