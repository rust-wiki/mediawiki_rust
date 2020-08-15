use thiserror::Error;

/// An error type for all errors which this library can produce.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Url: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("SystemTime: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    #[error("Reqwest: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Request: Invalid header: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("Request: ToStr: {0}")]
    ReqwestToStr(#[from] reqwest::header::ToStrError),

    #[error("Serde JSON: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Hmac: Invalid key length: {0}")]
    HmacInvalidKeyLength(#[from] hmac::crypto_mac::InvalidKeyLength),

    #[error(transparent)]
    Page(Box<crate::page::PageError>),

    #[error("{0}")]
    String(String),

    #[error("{0}")]
    Str(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<crate::page::PageError> for Error {
    fn from(err: crate::page::PageError) -> Self {
        Error::Page(Box::new(err))
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::String(err)
    }
}

impl From<&'static str> for Error {
    fn from(err: &'static str) -> Self {
        Error::Str(err)
    }
}
