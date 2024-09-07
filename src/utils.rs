use std::fs;
use infer::Infer;

use crate::constants::{
    DEF_THUMB_DIR, MIME_DEB, MIME_DOC, MIME_ELF, MIME_EXE, MIME_JPG, MIME_MCO, MIME_PDF, MIME_PNG, MIME_PPT, MIME_TXT, MIME_UAR, MIME_XCL
};

pub fn get_thumb_path(file_type: Option<String>) -> String {
    match file_type.as_deref() {
        Some(MIME_PDF) => format!("{}/pdf.png", DEF_THUMB_DIR),
        Some(MIME_DOC) => format!("{}/doc.png", DEF_THUMB_DIR),
        Some(MIME_XCL) => format!("{}/xls.png", DEF_THUMB_DIR),
        Some(MIME_PPT) => format!("{}/ppt.png", DEF_THUMB_DIR),
        Some(MIME_JPG) => format!("{}/jpg.png", DEF_THUMB_DIR),
        Some(MIME_PNG) => format!("{}/png.png", DEF_THUMB_DIR),
        Some(MIME_TXT) => format!("{}/txt.png", DEF_THUMB_DIR),
        Some(MIME_EXE) => format!("{}/exe.png", DEF_THUMB_DIR),
        Some(MIME_MCO) => format!("{}/mco.png", DEF_THUMB_DIR),
        Some(MIME_ELF) | Some(MIME_UAR) | Some(MIME_DEB) => format!("{}/elf.png", DEF_THUMB_DIR),
        _ => format!("{}/def.png", DEF_THUMB_DIR),
    }
}

pub fn detect_file_type(file_path: &str) -> Option<String> {
    let buf = match fs::read(file_path) {
        Ok(data) => data,
        Err(e) => {
            log::info!("## Mime: ERR: {}", e);
            return None
        },
    };

    let info = Infer::new();

    if let Some(kind) = info.get(&buf) {
        log::info!("## Mime: {}", kind);
        return Some(kind.mime_type().to_string());
    }

    if buf.starts_with(b"PK") && buf.len() > 30 {
        if buf[30..].windows(4).any(|window| window == b"word") {
            log::info!("## Mime: DOC");
            return Some(MIME_DOC.to_string());
        } else if buf[30..].windows(4).any(|window| window == b"xl/") {
            log::info!("## Mime: Sheet");
            return Some(MIME_XCL.to_string());
        } else if buf[30..].windows(4).any(|window| window == b"ppt/") {
            log::info!("## Mime: PPT");
            return Some(MIME_PPT.to_string());
        }
    }

    if buf.starts_with(b"MZ") {
        log::info!("## Mime: EXE");
        return Some(MIME_EXE.to_string()); // ".exe" file
    }

    if buf.starts_with(b"\x7FELF") || buf.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        log::info!("## Mime: ELF");
        return Some(MIME_ELF.to_string()); // ELF file (Linux)
    }

    if buf.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) || buf.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) {
        log::info!("## Mime: Mach-o");
        return Some(MIME_MCO.to_string()); // Mac executable
    }
    log::info!("## Mime: NONE");
    None
}