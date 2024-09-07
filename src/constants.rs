// Messages
pub const MESSAGE_OK: &str = "ok";
pub const MESSAGE_CAN_NOT_FETCH_DATA: &str = "Can not fetch data";
pub const MESSAGE_CAN_NOT_INSERT_DATA: &str = "Can not insert data";
pub const MESSAGE_CAN_NOT_UPDATE_DATA: &str = "Can not update data";
pub const MESSAGE_CAN_NOT_DELETE_DATA: &str = "Can not delete data";
pub const MESSAGE_SIGNUP_SUCCESS: &str = "Signup successfully";
pub const MESSAGE_SIGNUP_FAILED: &str = "Error while signing up, please try again";
pub const MESSAGE_LOGIN_SUCCESS: &str = "Login successfully";
pub const MESSAGE_LOGIN_FAILED: &str = "Wrong username or password, please try again";
pub const MESSAGE_USER_NOT_FOUND: &str = "User not found, please signup";
pub const MESSAGE_LOGOUT_SUCCESS: &str = "Logout successfully";
pub const MESSAGE_PROCESS_TOKEN_ERROR: &str = "Error while processing token";
pub const MESSAGE_INVALID_TOKEN: &str = "Invalid token, please login again";
pub const MESSAGE_INTERNAL_SERVER_ERROR: &str = "Internal Server Error";

// Bad request messages
pub const MESSAGE_TOKEN_MISSING: &str = "Token is missing";
pub const MESSAGE_BAD_REQUEST: &str = "Bad Request";

// Headers
pub const AUTHORIZATION: &str = "Authorization";

// Misc
pub const EMPTY: &str = "";

// ignore routes
pub const IGNORE_ROUTES: [&str; 2] = ["/login", "/register"];

// dirctories
pub const PATH_TO_FILES: &str = "./src/files/";
pub const DEF_THUMB_DIR: &str = "./src/files/def_thumbs/";

pub const MIME_PDF: &str = "application/pdf";
pub const MIME_XCL: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
pub const MIME_PPT: &str = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
pub const MIME_JPG: &str = "image/jpeg";
pub const MIME_PNG: &str = "image/png";
pub const MIME_TXT: &str = "text/plain";
pub const MIME_EXE: &str = "application/vnd.microsoft.portable-executable";
pub const MIME_ELF: &str = "application/x-elf";
pub const MIME_MCO: &str = "application/x-mach-o";
pub const MIME_DOC: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

// use bin.png for these
pub const MIME_OLE: &str = "application/x-ole-storage";

// archives -- arc.png
pub const MIME_DEB: &str = "application/vnd.debian.binary-package";
pub const MIME_UAR: &str = "application/x-unix-archive";

