use std::collections::HashMap;

#[cfg(test)]
extern crate lazy_static;
#[cfg(test)]
#[macro_use]
extern crate serde_json;
extern crate hmac;
extern crate nanoid;

#[macro_export]
/// To quickly create a param set.
/// Example: `params!["action"=>"query","meta"=>"siteinfo","siprop"=>"general|namespaces|namespacealiases|libraries|extensions|statistics"]`
macro_rules! params {
    ($( $key: expr => $val: expr ),* $(,)?) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key.into(), $val.into()); )*
         map
    }}
}

pub type Params = HashMap<String, String>;

pub use reqwest;

pub mod api;
pub mod api_sync;
pub mod error;
pub mod method;
pub mod page;
pub mod title;
pub mod user;
