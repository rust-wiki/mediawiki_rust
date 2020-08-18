use serde_json::Value;
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

    #[error("Login failed: {reason}")]
    Login { reason: String },

    #[error("g_consumer_secret or g_token_secret not set")]
    MissingSecret,

    #[error("url.host_str is None")]
    MissingUrlHost,

    #[error("Could not get token: {value:?}")]
    MissingToken { value: Value },

    #[error("No {value:?} value in site info")]
    MissingSiteInfo { value: String },

    #[error("Missing key {0:?} in result")]
    MissingKey(&'static str),

    #[error("{0} called but self.oauth is None")]
    MissingOauth(&'static str),

    #[error("{uri:?} does not start with {base_uri:?}")]
    BadUri { uri: String, base_uri: String },

    #[error(
        "Max attempts reached [MAXLAG] after {attempts} attempts, cumulative maxlag {cumulative}"
    )]
    MaxAttemptsReached { attempts: u64, cumulative: u64 },
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<crate::page::PageError> for Error {
    fn from(err: crate::page::PageError) -> Self {
        Error::Page(Box::new(err))
    }
}
