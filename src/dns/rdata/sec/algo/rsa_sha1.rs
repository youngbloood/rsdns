use anyhow::{anyhow, Error};
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{
        der::Writer, DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
        LineEnding,
    },
    Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha1::Sha1;
use std::{fs::File, path::Path};

use super::common::hash_sha1;

pub struct RsaSha1 {
    pub_key: RsaPublicKey,
    priv_key: Option<RsaPrivateKey>,
}

impl RsaSha1 {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to new rsa private key");
        let pub_key = RsaPublicKey::from(&priv_key);

        Self {
            priv_key: Some(priv_key),
            pub_key: pub_key,
        }
    }

    /// Save the pub_key & priv_key to indicate file.
    ///
    /// The private key only be saved as pkcs8 der or pem type.
    pub fn save_to(&self, pub_file: &str, priv_file: &str) -> Result<(), Error> {
        let write_to_file = |filename: &str, bts: &[u8]| -> Result<(), Error> {
            let mut fopt = File::options();
            fopt.write(true).create(true);
            let mut fd = fopt.open(filename)?;
            fd.write(bts)?;
            Ok(())
        };

        let mut _pub_bts = vec![];
        if Path::new(pub_file).extension().unwrap() == "der" {
            _pub_bts = self.pub_key.to_public_key_der()?.into_vec();
        } else {
            _pub_bts = self
                .pub_key
                .to_public_key_pem(LineEnding::LF)?
                .as_bytes()
                .to_vec();
        }
        write_to_file(pub_file, &_pub_bts)?;

        // private key
        if self.priv_key.is_none() {
            return Ok(());
        }
        let mut _priv_bts = vec![];
        if Path::new(priv_file).extension().unwrap() == "der" {
            _priv_bts = self
                .priv_key
                .as_ref()
                .unwrap()
                .to_pkcs8_der()?
                .as_bytes()
                .to_vec();
        } else {
            _priv_bts = self
                .priv_key
                .as_ref()
                .unwrap()
                .to_pkcs8_pem(LineEnding::LF)?
                .as_bytes()
                .to_vec();
        }
        write_to_file(priv_file, &_priv_bts)?;
        Ok(())
    }

    /// Parse public key & private key from the indicate file.
    ///
    /// The priv_file can be empty. Then will only parse public key.
    ///
    /// Support the '.der' and '.pem' file type
    pub fn from_file(pub_file: &str, priv_file: &str) -> Result<Self, Error> {
        let mut rs = Self::new();
        if Path::new(pub_file).extension().unwrap() == "der" {
            rs.pub_key = RsaPublicKey::read_public_key_der_file(pub_file)?;
        } else {
            rs.pub_key = RsaPublicKey::read_public_key_pem_file(pub_file)?;
        }

        if priv_file.len() == 0 {
            rs.priv_key = None;
            return Ok(rs);
        }

        if Path::new(priv_file).extension().unwrap() == "der" {
            match RsaPrivateKey::read_pkcs8_der_file(priv_file) {
                Ok(sk) => {
                    rs.priv_key = Some(sk);
                }
                Err(_) => {
                    rs.priv_key = Some(RsaPrivateKey::read_pkcs1_der_file(priv_file)?);
                }
            }
        } else {
            match RsaPrivateKey::read_pkcs8_pem_file(priv_file) {
                Ok(sk) => {
                    rs.priv_key = Some(sk);
                }
                Err(_) => {
                    rs.priv_key = Some(RsaPrivateKey::read_pkcs1_pem_file(priv_file)?);
                }
            }
        }

        Ok(rs)
    }

    /// Encrypt the message with public key.
    pub fn encrypt_msg(&self, src: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rng = rand::thread_rng();
        let encrypted = self.pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, src)?;

        Ok(encrypted)
    }

    /// Dencrypt the ciphertest with private key.
    pub fn dencrypt_msg(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.priv_key.is_none() {
            return Err(anyhow!("not has private key to dencrypt"));
        }
        let result = self
            .priv_key
            .as_ref()
            .unwrap()
            .decrypt(Pkcs1v15Encrypt, ciphertext)?;

        Ok(result)
    }

    fn new_pkcs1v15(&self) -> Pkcs1v15Sign {
        let mut pkcs1v15_padding: Pkcs1v15Sign = Pkcs1v15Sign::new::<Sha1>();
        // ref: https://www.rfc-editor.org/rfc/rfc3110.html#section-3
        pkcs1v15_padding.prefix = Box::new([
            30_u8, 21, 30, 09, 06, 05, 0x2B, 0x0E, 03, 02, 0x1A, 05, 00, 04, 14,
        ]);

        pkcs1v15_padding
    }

    /// Sign the digest with the private key.
    ///
    /// Digest is originial data and will be hashed with sha1.
    ///
    /// The default padding is Pkcs1v15Sign.
    pub fn sign_digest(&self, digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if self.priv_key.is_none() {
            return Err(anyhow!("not has private key to dencrypt"));
        }

        let hashed = hash_sha1(digest);
        let signer = self
            .priv_key
            .as_ref()
            .unwrap()
            .sign(self.new_pkcs1v15(), &hashed)?;
        Ok((hashed, signer))
    }

    /// Verify the signer with the public key.
    ///
    /// Digest is originial data and will be hashed with sha1.
    ///
    /// The default padding is Pkcs1v15Sign.
    pub fn verify_digest(&self, digest: &[u8], signer: &[u8]) -> Result<(), Error> {
        let hashed = hash_sha1(digest);
        self.pub_key.verify(self.new_pkcs1v15(), &hashed, signer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn new_rsasha1_with_priv() -> RsaSha1 {
        RsaSha1::from_file(
            "./src/dns/rdata/sec/algo/test_data/rsa_sha1.pub",
            "./src/dns/rdata/sec/algo/test_data/rsa_sha1.priv.pem",
        )
        .unwrap()
    }

    fn new_rsasha1_without_priv() -> RsaSha1 {
        RsaSha1::from_file("./src/dns/rdata/sec/algo/test_data/rsa_sha1.pub", "").unwrap()
    }

    #[test]
    #[ignore = "invoke by manually when no pub&priv file in test_data"]
    pub fn test_rsasha1_save_to() {
        let rs = RsaSha1::new();
        if let Err(e) = rs.save_to(
            "./src/dns/rdata/sec/algo/test_data/rsa_sha1.pub",
            "./src/dns/rdata/sec/algo/test_data/rsa_sha1.priv.pem",
        ) {
            panic!("{}", e)
        }
    }

    #[test]
    pub fn test_rsasha1_from() {
        let rs = RsaSha1::from_file(
            "./src/dns/rdata/sec/algo/test_data/rsa_sha1.pub",
            "./src/dns/rdata/sec/algo/test_data/rsa_sha1.priv.pem",
        );
        if rs.is_err() {
            panic!("{:?}", rs.err());
        }

        let rs = RsaSha1::from_file("./src/dns/rdata/sec/algo/test_data/rsa_sha1.pub", "");
        if rs.is_err() {
            panic!("{:?}", rs.err());
        }
    }

    #[test]
    pub fn test_rsasha1_encrypt_msg() {
        let rs = new_rsasha1_with_priv();
        let ciphertext = rs.encrypt_msg(b"hello world").unwrap();
        println!("{:?}", ciphertext);
    }

    #[test]
    pub fn test_rsasha1_dencrypt_msg() {
        let ciphertexts: &[&[u8]] = &[
            &[
                129_u8, 108, 118, 95, 105, 223, 19, 109, 137, 103, 107, 225, 78, 26, 98, 95, 132,
                62, 129, 182, 129, 30, 131, 176, 159, 71, 132, 171, 59, 38, 88, 37, 235, 24, 201,
                97, 96, 189, 168, 64, 91, 94, 121, 111, 93, 130, 122, 76, 153, 157, 206, 166, 16,
                147, 196, 14, 143, 113, 141, 133, 146, 239, 221, 106, 237, 150, 183, 54, 154, 40,
                71, 119, 181, 245, 141, 71, 229, 88, 175, 156, 66, 13, 94, 244, 141, 12, 229, 120,
                106, 165, 36, 42, 237, 251, 58, 128, 73, 137, 128, 223, 28, 108, 17, 0, 101, 244,
                200, 132, 163, 16, 190, 46, 203, 228, 235, 198, 15, 165, 85, 207, 195, 11, 183,
                127, 107, 252, 110, 217, 61, 35, 128, 196, 50, 230, 169, 17, 191, 31, 82, 240, 170,
                143, 28, 19, 25, 16, 152, 45, 236, 82, 195, 70, 15, 211, 129, 207, 113, 247, 6,
                175, 223, 83, 198, 119, 58, 40, 173, 107, 29, 51, 54, 96, 249, 91, 126, 100, 174,
                116, 68, 199, 174, 17, 122, 141, 69, 237, 1, 126, 15, 99, 132, 58, 41, 211, 228,
                202, 0, 72, 150, 132, 232, 248, 148, 182, 110, 25, 159, 50, 64, 2, 142, 15, 28,
                108, 88, 199, 246, 35, 18, 139, 63, 157, 72, 170, 55, 108, 97, 200, 113, 178, 5,
                30, 88, 28, 1, 69, 35, 20, 183, 197, 4, 68, 3, 70, 147, 157, 151, 172, 100, 91,
                149, 245, 82, 95, 19, 51,
            ],
            &[
                47, 92, 49, 154, 57, 206, 252, 94, 177, 7, 56, 111, 231, 156, 114, 34, 35, 183, 55,
                42, 86, 42, 0, 119, 105, 14, 204, 233, 98, 93, 206, 255, 53, 192, 16, 228, 37, 111,
                198, 217, 127, 186, 136, 160, 165, 247, 250, 207, 125, 109, 212, 94, 91, 127, 137,
                67, 57, 200, 9, 128, 166, 37, 124, 153, 168, 141, 235, 176, 246, 189, 65, 185, 2,
                141, 41, 151, 246, 207, 21, 236, 56, 151, 60, 40, 129, 9, 213, 227, 63, 173, 104,
                195, 152, 43, 144, 2, 163, 41, 115, 159, 116, 55, 146, 31, 17, 147, 13, 160, 207,
                138, 70, 106, 121, 199, 160, 97, 90, 101, 59, 191, 131, 244, 0, 145, 211, 40, 116,
                140, 73, 240, 49, 55, 100, 74, 186, 199, 229, 178, 145, 130, 243, 124, 125, 209,
                14, 170, 245, 81, 153, 20, 2, 60, 145, 249, 250, 48, 48, 168, 219, 33, 14, 125,
                135, 115, 228, 77, 113, 197, 24, 0, 23, 198, 170, 90, 117, 106, 136, 148, 139, 185,
                16, 94, 198, 2, 55, 140, 192, 189, 133, 152, 48, 26, 221, 92, 149, 82, 55, 171,
                133, 105, 2, 109, 3, 205, 239, 239, 178, 63, 248, 222, 20, 247, 24, 156, 135, 48,
                139, 7, 137, 211, 100, 2, 169, 143, 148, 177, 138, 134, 56, 82, 17, 145, 81, 50,
                117, 175, 186, 195, 182, 198, 81, 8, 100, 43, 83, 32, 97, 156, 30, 234, 222, 222,
                166, 33, 180, 36,
            ],
            &[
                173, 43, 39, 180, 133, 133, 156, 232, 184, 87, 189, 54, 139, 218, 39, 94, 111, 60,
                192, 9, 22, 163, 62, 148, 223, 112, 220, 143, 154, 14, 212, 166, 158, 153, 155,
                237, 150, 80, 253, 155, 85, 60, 103, 204, 157, 59, 154, 124, 48, 1, 57, 26, 178,
                160, 158, 114, 17, 94, 182, 60, 181, 105, 180, 237, 227, 134, 121, 123, 243, 226,
                173, 125, 189, 241, 169, 157, 102, 101, 171, 199, 190, 136, 168, 86, 83, 51, 56,
                183, 146, 66, 144, 63, 19, 194, 161, 120, 227, 190, 176, 224, 163, 106, 48, 172,
                160, 223, 53, 125, 4, 152, 147, 165, 69, 19, 195, 246, 48, 112, 166, 175, 100, 176,
                63, 46, 179, 210, 137, 194, 175, 223, 164, 89, 168, 233, 171, 151, 233, 122, 157,
                5, 94, 100, 142, 154, 127, 207, 167, 73, 59, 188, 148, 147, 27, 109, 67, 8, 233,
                24, 26, 139, 249, 78, 191, 244, 70, 70, 60, 113, 213, 39, 168, 249, 82, 204, 78,
                20, 214, 80, 189, 150, 18, 215, 4, 221, 45, 97, 140, 177, 76, 62, 143, 194, 129,
                96, 187, 251, 251, 79, 159, 18, 235, 21, 57, 224, 83, 90, 55, 204, 58, 60, 47, 43,
                195, 129, 49, 79, 1, 159, 224, 175, 137, 4, 25, 130, 119, 77, 117, 10, 241, 213,
                198, 192, 10, 168, 44, 15, 27, 187, 142, 84, 233, 181, 136, 7, 78, 21, 15, 157, 78,
                183, 196, 24, 161, 184, 46, 66,
            ],
        ];

        // no priv_key
        let rs = new_rsasha1_without_priv();
        for ciphertext in ciphertexts {
            assert_eq!(true, rs.dencrypt_msg(ciphertext).is_err());
        }

        // has priv_key
        let rs = new_rsasha1_with_priv();
        for ciphertext in ciphertexts {
            let result = rs.dencrypt_msg(ciphertext);
            assert_eq!(false, result.is_err());
            assert_eq!(b"hello world" as &[u8], result.unwrap());
        }
    }

    #[test]
    pub fn test_rsasha1_sign_digest() {
        // has priv_key
        let rs = new_rsasha1_with_priv();
        let result = rs.sign_digest(b"hello world" as &[u8]);
        if result.is_err() {
            panic!("{:?}", result.err());
        }
        assert_eq!(true, result.is_ok());
        println!("hashed:{:?}", result.as_ref().unwrap().0);
        println!("signer:{:?}", result.as_ref().unwrap().1);
    }

    #[test]
    pub fn test_rsasha1_verify_digest() {
        let signers: &[(&[u8], &[u8])] = &[(
            b"hello world",
            &[
                88, 119, 138, 202, 151, 177, 69, 0, 48, 107, 139, 63, 6, 220, 72, 57, 166, 186,
                189, 77, 40, 40, 50, 206, 150, 17, 184, 197, 201, 195, 162, 57, 200, 40, 106, 172,
                198, 241, 128, 125, 187, 239, 216, 12, 51, 70, 47, 143, 227, 50, 64, 239, 110, 4,
                17, 180, 219, 105, 156, 150, 47, 87, 239, 55, 138, 139, 245, 64, 168, 113, 252, 57,
                117, 174, 53, 67, 76, 151, 117, 208, 2, 178, 81, 119, 204, 197, 77, 38, 59, 165,
                88, 183, 100, 181, 23, 22, 157, 247, 191, 162, 103, 199, 58, 152, 63, 102, 228,
                119, 67, 9, 203, 58, 229, 28, 170, 253, 228, 188, 127, 153, 120, 189, 141, 170, 61,
                4, 225, 36, 96, 154, 141, 239, 151, 45, 6, 83, 114, 222, 165, 42, 132, 112, 198,
                48, 115, 160, 26, 113, 26, 182, 63, 44, 0, 41, 151, 139, 174, 105, 202, 211, 239,
                246, 22, 234, 247, 243, 77, 238, 117, 192, 169, 233, 92, 242, 17, 163, 115, 192,
                12, 100, 226, 104, 194, 187, 46, 196, 110, 55, 186, 136, 175, 151, 255, 213, 90,
                189, 235, 206, 242, 201, 114, 76, 125, 50, 35, 86, 45, 83, 123, 253, 198, 22, 79,
                54, 247, 45, 1, 217, 90, 175, 100, 139, 85, 254, 112, 139, 87, 183, 9, 222, 114,
                161, 212, 247, 129, 176, 63, 26, 72, 186, 242, 99, 91, 231, 51, 241, 133, 241, 190,
                134, 219, 35, 164, 14, 189, 81,
            ],
        )];
        // has priv_key
        let rs = new_rsasha1_without_priv();
        for tpl in signers {
            let result = rs.verify_digest(tpl.0, tpl.1);
            if result.is_err() {
                panic!("{:?}", result.err());
            }
            assert_eq!(true, result.is_ok());
            println!("{:?}", result.unwrap());
        }
    }
}
