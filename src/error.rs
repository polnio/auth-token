use aes_gcm::aes::cipher::InvalidLength as AesInvalidLength;

#[derive(Debug)]
pub enum Error {
    InvalidKey(AesInvalidLength),
    Bincode(bincode::Error),
    Encryption,
    Decryption,
    InvalidBase64,
    InvalidToken,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
