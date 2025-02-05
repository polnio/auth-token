pub mod error;

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
pub use error::{Error, Result};

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, OsRng},
    Aes256Gcm, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};

pub struct Encrypter {
    inner: Aes256Gcm,
}

impl Encrypter {
    pub fn new(key: &[u8]) -> Result<Self> {
        let inner = Aes256Gcm::new_from_slice(key).map_err(Error::InvalidKey)?;
        Ok(Self { inner })
    }

    pub fn encrypt<T: Serialize>(&self, data: &T) -> Result<String> {
        let to_encrypt = bincode::serialize(data).map_err(|e| Error::Bincode(e))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = self
            .inner
            .encrypt(Nonce::from_slice(&nonce), to_encrypt.as_slice())
            .map_err(|_| Error::Encryption)?;
        let mut result = Vec::with_capacity(nonce.len() + encrypted.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted);
        Ok(BASE64_URL_SAFE_NO_PAD.encode(result))
    }

    pub fn decrypt<T: for<'de> Deserialize<'de>>(&self, data: &str) -> Result<T> {
        let data = BASE64_URL_SAFE_NO_PAD
            .decode(data)
            .map_err(|_| Error::InvalidBase64)?;
        let (nonce, ciphertext) = data.split_at_checked(12).ok_or(Error::InvalidToken)?;
        let nonce = Nonce::from_slice(nonce);
        let decrypted = self
            .inner
            .decrypt(nonce, ciphertext)
            .map_err(|_| Error::Decryption)?;
        let result = bincode::deserialize(&decrypted).map_err(|e| Error::Bincode(e))?;
        Ok(result)
    }
}
