use std::collections::BTreeMap;

/// A key/value collection containing strings.
/// This is used for mediawiki requests.
pub type Params = BTreeMap<String, String>;

// TODO: Crate a wrapper struct
