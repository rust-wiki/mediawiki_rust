use std::fmt;

/// Supported HTTP methods
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Method {
    /// GET method
    Get,
    /// POST method
    Post,
}

impl Method {
    /// Converts `Get` to `"GET"` and `Post` to `"POST"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
