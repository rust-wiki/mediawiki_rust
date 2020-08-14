use std::fmt;

/// A catch-all error type for all errors which this library can produce.
///
/// It's effectively a wrapper around `Box<dyn Error>` which you can treat as a regular error type.
#[derive(Debug)]
pub struct Error {
    err: Box<dyn std::error::Error + Send + Sync>,
}

impl Error {
    pub fn into_boxed(self) -> Box<dyn std::error::Error + Send + Sync> {
        self.err
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.err.fmt(f)
    }
}

impl std::error::Error for Error {}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Self {
        {
            Self { err: Box::new(err) }
        }
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(err: std::time::SystemTimeError) -> Self {
        Self { err: Box::new(err) }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self { err: Box::new(err) }
    }
}

impl From<reqwest::header::InvalidHeaderValue> for Error {
    fn from(err: reqwest::header::InvalidHeaderValue) -> Self {
        Self { err: Box::new(err) }
    }
}

impl From<reqwest::header::ToStrError> for Error {
    fn from(err: reqwest::header::ToStrError) -> Self {
        Self { err: Box::new(err) }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self { err: Box::new(err) }
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for Error {
    fn from(err: hmac::crypto_mac::InvalidKeyLength) -> Self {
        Self { err: Box::new(err) }
    }
}

impl From<crate::page::PageError> for Error {
    fn from(err: crate::page::PageError) -> Self {
        Self { err: Box::new(err) }
    }
}

impl From<StringError> for Error {
    fn from(err: StringError) -> Self {
        Self { err: Box::new(err) }
    }
}

/// A simple wrapper for string errors.
///
/// Using a regular string as an error type is not a good idea since it doens't compose very well.
#[derive(Clone, Debug)]
pub(crate) struct StringError {
    s: String,
}

impl StringError {
    pub(crate) fn new<S: Into<String>>(s: S) -> Self {
        StringError { s: s.into() }
    }
}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.s.fmt(f)
    }
}

impl std::error::Error for StringError {}
