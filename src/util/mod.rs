use std::{
    ffi::OsStr,
    fs::{self, DirEntry},
};

use anyhow::Error;
use base64::{
    alphabet::STANDARD,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use once_cell::sync::Lazy;

pub static BASE64_ENGINE: Lazy<GeneralPurpose> =
    Lazy::new(|| GeneralPurpose::new(&STANDARD, GeneralPurposeConfig::new()));

/// is_compressed judge the rrs weather use the compress.
/// if the third byte is zero and the first byte's first and second bit is 1, it represent compressed. or not
/// ref: https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
pub fn is_compressed(pointer: [u8; 2]) -> (usize, bool) {
    let mut off = [pointer[0], pointer[1]];
    off[0] &= 0b0011_1111;
    return (
        u16::from_be_bytes(off) as usize,
        pointer[0] & 0b1100_0000 == 0b1100_0000,
    );
}

pub fn is_compressed_wrap(raw: &[u8]) -> (usize, bool) {
    if raw.len() < 2 {
        return (0, false);
    }
    return is_compressed(raw[..2].try_into().expect("get the compressed pointer"));
}

pub fn encode_name(name: &str) -> &str {
    if name.len() == 0 {
        return "NONE";
    }
    return name;
}

pub fn decode_name(src: &str) -> &str {
    if src == "NONE" {
        return "";
    }
    return src;
}

pub fn visit_dirs(dir: &str) -> Result<Vec<String>, Error> {
    let mut list = vec![];
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let sub_dir = path.to_str().unwrap();
            list.extend(visit_dirs(sub_dir)?);
        } else {
            list.push(path.to_str().unwrap().to_string())
        }
    }

    Ok(list)
}

pub fn visit_dirs_with_cb(dir: &str, cb: &dyn Fn(&DirEntry)) -> Result<(), Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let sub_dir = path.to_str().unwrap();
            visit_dirs_with_cb(sub_dir, cb)?;
        } else {
            cb(&entry)
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn test_base64_encode() {
        let out = BASE64_ENGINE.encode("123456");
        assert_eq!("MTIzNDU2", out);

        let out = BASE64_ENGINE.encode("!@#$%^&*()_+ []|';,./?><:\"~`");
        assert_eq!("IUAjJCVeJiooKV8rIFtdfCc7LC4vPz48OiJ+YA==", out);
    }

    #[test]
    fn test_base64_decode() {
        let out = BASE64_ENGINE.decode("MTIzNDU2").unwrap();
        let s = unsafe { String::from_utf8_unchecked(out) };
        assert_eq!("123456", s);

        let out = BASE64_ENGINE
            .decode("IUAjJCVeJiooKV8rIFtdfCc7LC4vPz48OiJ+YA==")
            .unwrap();
        let s = unsafe { String::from_utf8_unchecked(out) };
        assert_eq!("!@#$%^&*()_+ []|';,./?><:\"~`", s);
    }

    #[test]
    fn test_visit_dirs() {
        let filenames = visit_dirs("./").unwrap();
        println!("filenames = {:?}", filenames);
    }

    #[test]
    fn test_visit_dirs_with_cb() {
        let result = visit_dirs_with_cb("./", &|et: &DirEntry| {
            println!("path = {:?}", et.path().to_str().unwrap())
        });
        assert_eq!(true, result.is_ok());
    }
}
