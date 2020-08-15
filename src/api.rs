/*!
The `Api` class serves as a univeral interface to a MediaWiki API.
*/

#![deny(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
//trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]

extern crate base64;
extern crate cookie;
extern crate nanoid;
extern crate reqwest;
extern crate sha1;

use crate::error::Result;
use crate::hmac::{Mac, NewMac};
use crate::title::Title;
use crate::{method::Method, user::User, Params};
use cookie::{Cookie, CookieJar};
use nanoid::nanoid;
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{thread, time};
use url::Url;

/// Alias for a namespace (could be -1 for Special pages etc.)
pub type NamespaceID = i64;

const DEFAULT_USER_AGENT: &str = "Rust mediawiki API";
const DEFAULT_MAXLAG: Option<u64> = Some(5);
const DEFAULT_MAX_RETRY_ATTEMPTS: u64 = 5;

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

/// `OAuthParams` contains parameters for OAuth requests
#[derive(Debug, Clone)]
pub struct OAuthParams {
    /// Consumer Key
    pub g_consumer_key: Option<String>,
    /// Consumer secret
    pub g_consumer_secret: Option<String>,
    /// Token key
    pub g_token_key: Option<String>,
    /// Token secret
    pub g_token_secret: Option<String>,
    g_user_agent: Option<String>,
    agent: Option<String>,
    consumer_key: Option<String>,
    consumer_secret: Option<String>,
    api_url: Option<String>,
    public_mw_oauth_url: Option<String>,
    tool: Option<String>,
}

impl OAuthParams {
    /// Imports data from JSON stored in the QuickStatements DB batch_oauth.serialized_json field
    pub fn new_from_json(j: &Value) -> Self {
        Self {
            g_consumer_key: j["gConsumerKey"].as_str().map(|s| s.to_string()),
            g_consumer_secret: j["gConsumerSecret"].as_str().map(|s| s.to_string()),
            g_token_key: j["gTokenKey"].as_str().map(|s| s.to_string()),
            g_token_secret: j["gTokenSecret"].as_str().map(|s| s.to_string()),
            g_user_agent: j["gUserAgent"].as_str().map(|s| s.to_string()),
            agent: j["params"]["agent"].as_str().map(|s| s.to_string()),
            consumer_key: j["params"]["consumerKey"].as_str().map(|s| s.to_string()),
            consumer_secret: j["params"]["consumerSecret"]
                .as_str()
                .map(|s| s.to_string()),
            api_url: j["apiUrl"].as_str().map(|s| s.to_string()),
            public_mw_oauth_url: j["publicMwOAuthUrl"].as_str().map(|s| s.to_string()),
            tool: j["tool"].as_str().map(|s| s.to_string()),
        }
    }
}

/// `Api` is the main class to interact with a MediaWiki API
#[derive(Debug, Clone)]
pub struct Api {
    api_url: String,
    site_info: Value,
    client: reqwest::Client,
    cookie_jar: CookieJar,
    user: User,
    user_agent: String,
    maxlag_seconds: Option<u64>,
    edit_delay_ms: Option<u64>,
    max_retry_attempts: u64,
    oauth: Option<OAuthParams>,
}

impl Api {
    /// Returns a new `Api` element, and loads the MediaWiki site info from the `api_url` site.
    /// This is done both to get basic information about the site, and to test the API.
    pub async fn new(api_url: &str) -> Result<Api> {
        Api::new_from_builder(api_url, reqwest::Client::builder()).await
    }

    /// Returns a new `Api` element, and loads the MediaWiki site info from the `api_url` site.
    /// This is done both to get basic information about the site, and to test the API.
    /// Uses a bespoke reqwest::ClientBuilder.
    pub async fn new_from_builder(api_url: &str, builder: reqwest::ClientBuilder) -> Result<Api> {
        let mut ret = Api {
            api_url: api_url.to_string(),
            site_info: serde_json::from_str(r"{}")?,
            client: builder.build()?,
            cookie_jar: CookieJar::new(),
            user: User::new(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
            maxlag_seconds: DEFAULT_MAXLAG,
            max_retry_attempts: DEFAULT_MAX_RETRY_ATTEMPTS,
            edit_delay_ms: None,
            oauth: None,
        };
        ret.load_site_info().await?;
        Ok(ret)
    }

    /// Returns the API url
    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Sets the OAuth parameters
    pub fn set_oauth(&mut self, oauth: Option<OAuthParams>) {
        self.oauth = oauth;
    }

    /// Returns a reference to the current OAuth parameters
    pub fn oauth(&self) -> &Option<OAuthParams> {
        &self.oauth
    }

    /// Returns a reference to the reqwest client
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Returns a mutable reference to the reqwest client
    pub fn client_mut(&mut self) -> &mut reqwest::Client {
        &mut self.client
    }

    /// Returns a reference to the current user object
    pub fn user(&self) -> &User {
        &self.user
    }

    /// Returns a mutable reference to the current user object
    pub fn user_mut(&mut self) -> &mut User {
        &mut self.user
    }

    /// Loads the current user info; returns Ok(()) is successful
    pub async fn load_current_user_info(&mut self) -> Result<()> {
        let mut user = std::mem::take(&mut self.user);
        self.load_user_info(&mut user).await?;
        self.user = user;
        Ok(())
    }

    /// Returns the maximum number of retry attempts
    pub fn max_retry_attempts(&self) -> u64 {
        self.max_retry_attempts
    }

    /// Sets the maximum number of retry attempts
    pub fn set_max_retry_attempts(&mut self, max_retry_attempts: u64) {
        self.max_retry_attempts = max_retry_attempts;
    }

    /// Returns a reference to the serde_json Value containing the site info
    pub fn get_site_info(&self) -> &Value {
        &self.site_info
    }

    /// Returns a serde_json Value in site info, within the `["query"]` object.
    pub fn get_site_info_value<'a>(&'a self, k1: &str, k2: &str) -> &'a Value {
        &self.get_site_info()["query"][k1][k2]
    }

    /// Returns a String from the site info, matching `["query"][k1][k2]`
    pub fn get_site_info_string<'a>(&'a self, k1: &str, k2: &str) -> Result<&'a str> {
        Ok(self
            .get_site_info_value(k1, k2)
            .as_str()
            .ok_or_else(|| format!("No 'query.{}.{}' value in site info", k1, k2))?)
    }

    /// Returns the raw data for the namespace, matching `["query"]["namespaces"][namespace_id]`
    pub fn get_namespace_info(&self, namespace_id: NamespaceID) -> &Value {
        self.get_site_info_value("namespaces", &namespace_id.to_string())
    }

    /// Returns the canonical namespace name for a namespace ID, if defined
    pub fn get_canonical_namespace_name(&self, namespace_id: NamespaceID) -> Option<&str> {
        let info = self.get_namespace_info(namespace_id);
        info["canonical"].as_str().or_else(|| info["*"].as_str())
    }

    /// Returns the local namespace name for a namespace ID, if defined
    pub fn get_local_namespace_name(&self, namespace_id: NamespaceID) -> Option<&str> {
        let info = self.get_namespace_info(namespace_id);
        info["*"].as_str().or_else(|| info["canonical"].as_str())
    }

    /// Loads the site info.
    /// Should only ever be called from `new()`
    async fn load_site_info(&mut self) -> Result<&Value> {
        let params = params![
            "action" => "query",
            "meta" => "siteinfo",
            "siprop"=> "general|namespaces|namespacealiases|libraries|extensions|statistics",
        ];
        self.site_info = self.get_query_api_json(params).await?;
        Ok(&self.site_info)
    }

    /// Merges two JSON objects that are MediaWiki API results.
    /// If an array already exists in the `a` object, it will be expanded with the array from the `b` object
    /// This allows for combining multiple API results via the `continue` parameter
    fn json_merge(&self, a: &mut Value, b: Value) {
        match (a, b) {
            (a @ &mut Value::Object(_), Value::Object(b)) => {
                if let Some(a) = a.as_object_mut() {
                    for (k, v) in b {
                        self.json_merge(a.entry(k).or_insert(Value::Null), v);
                    }
                }
            }
            (a @ &mut Value::Array(_), Value::Array(b)) => {
                if let Some(a) = a.as_array_mut() {
                    for v in b {
                        a.push(v);
                    }
                }
            }
            (a, b) => *a = b,
        }
    }

    /// Returns an empty parameter list
    pub fn no_params(&self) -> Params {
        HashMap::new()
    }

    /// Returns a token of a `token_type`, such as `login` or `csrf` (for editing)
    pub async fn get_token(&mut self, token_type: &str) -> Result<String> {
        let mut params = params!["action" => "query", "meta" => "tokens"];
        if !token_type.is_empty() {
            params.insert("type".to_string(), token_type.to_string());
        }
        let mut key = token_type.to_string();
        key += &"token";
        if token_type.is_empty() {
            key = "csrftoken".into()
        }
        let x = self.query_api_json_mut(params, Method::Get).await?;
        Ok(x["query"]["tokens"][&key]
            .as_str()
            .map(ToString::to_string)
            .ok_or_else(|| format!("Could not get token: {:?}", x))?)
    }

    /// Calls `get_token()` to return an edit token
    pub async fn get_edit_token(&mut self) -> Result<String> {
        self.get_token("csrf").await
    }

    /// Same as `get_query_api_json` but automatically loads all results via the `continue` parameter
    pub async fn get_query_api_json_all(&self, params: &Params) -> Result<Value> {
        self.get_query_api_json_limit(params, None).await
    }

    /// Tries to return the len() of an API query result. Returns 0 if unknown
    fn query_result_count(&self, result: &Value) -> usize {
        match result["query"].as_object() {
            Some(query) => query
                .iter()
                .filter_map(|(_key, part)| match part.as_array() {
                    Some(a) => Some(a.len()),
                    None => None,
                })
                .next()
                .unwrap_or(0),
            None => 0, // Don't know size
        }
    }

    /// Same as `get_query_api_json` but automatically loads more results via the `continue` parameter
    pub async fn get_query_api_json_limit(
        &self,
        params: &Params,
        max: Option<usize>,
    ) -> Result<Value> {
        let mut cont = HashMap::<String, String>::new();
        let mut ret = serde_json::json!({});
        loop {
            let mut params_cont = params.clone();
            for (k, v) in &cont {
                params_cont.insert(k.to_string(), v.to_string());
            }
            let result = self.get_query_api_json(params_cont).await?;
            cont.clear();
            let conti = result["continue"].clone();
            self.json_merge(&mut ret, result);
            if let Some(m) = max {
                if self.query_result_count(&ret) >= m {
                    break;
                }
            }
            match conti {
                Value::Object(obj) => {
                    cont.clear();
                    obj.iter().filter(|x| x.0 != "continue").for_each(|x| {
                        let continue_value =
                            x.1.as_str().map_or(x.1.to_string(), |s| s.to_string());
                        cont.insert(x.0.to_string(), continue_value);
                    });
                }
                _ => {
                    break;
                }
            }
        }
        if let Some(x) = ret.as_object_mut() {
            x.remove("continue");
        }

        Ok(ret)
    }

    /*
    /// Same as `get_query_api_json` but automatically loads more results via the `continue` parameter
    pub async fn get_query_api_json_limit(
        &self,
        params: &Params,
        max: Option<usize>,
    ) -> Result<Value, Error> {
        self.get_query_api_json_limit_iter(params, max).await
            .try_fold(Value::Null, |mut acc, result| {
                self.json_merge(&mut acc, result?);
                Ok(acc)
            })
    }

    /// Same as `get_query_api_json` but automatically loads more results via the `continue` parameter.
    /// Returns an iterator; each item is a "page" of results.
    pub async fn get_query_api_json_limit_iter<'a>(
        &'a self,
        params: &Params,
        max: Option<usize>,
    ) -> impl Iterator<Item = Result<Value, Error>> + 'a {
        struct ApiQuery<'a> {
            api: &'a Api,
            params: Params,
            values_remaining: Option<usize>,
            continue_params: Value,
        }

        impl<'a> Iterator for ApiQuery<'a> {
            type Item = Result<Value, Error>;

            fn next(&mut self) -> Option<Self::Item> {
                if let Some(0) = self.values_remaining {
                    return None;
                }

                let mut current_params = self.params.clone();
                if let Value::Object(obj) = &self.continue_params {
                    current_params.extend(
                        obj.iter()
                            .filter(|x| x.0 != "continue")
                            // The default to_string() method for Value puts double-quotes around strings
                            .map(|(k, v)| {
                                (k.to_string(), v.as_str().map_or(v.to_string(), Into::into))
                            }),
                    );
                }

                async {
                let query_result =
                self.api.get_query_api_json(&current_params).await;

                let ret = match query_result {
                    Ok(mut result) => {
                        self.continue_params = result["continue"].clone();
                        if self.continue_params.is_null() {
                            self.values_remaining = Some(0);
                        } else if let Some(num) = self.values_remaining {
                            self.values_remaining =
                                Some(num.saturating_sub(self.api.query_result_count(&result)));
                        }
                        result.as_object_mut().map(|r| r.remove("continue"));
                        Ok(result)
                    }
                    Err(e) => {
                        self.values_remaining = Some(0);
                        //Err(Box::new(e) as Error)
                        let s = format!("{:?}",e);
                        let err: Box<dyn Error + Send + Sync + Send + Sync> = StringError::new(s);
                        Err(err as Error)
                    }
                } ;
                Some(ret)
            }
            }
        }

        ApiQuery {
            api: self,
            params: params.clone(),
            values_remaining: max,
            continue_params: Value::Null,
        }
    }
    */

    /// Runs a query against the MediaWiki API, using `method` GET or POST.
    /// Parameters are a hashmap; `format=json` is enforced.
    pub async fn query_api_json(&self, mut params: Params, method: Method) -> Result<Value> {
        let mut attempts_left = self.max_retry_attempts;
        params.insert("format".to_string(), "json".to_string());
        let mut cumulative: u64 = 0;
        loop {
            self.set_cumulative_maxlag_params(&mut params, method, cumulative);
            let t = self.query_api_raw(&params, method).await?;
            let v: Value = serde_json::from_str(&t)?;
            match self.check_maxlag(&v) {
                Some(lag_seconds) => {
                    if attempts_left == 0 {
                        return Err(format!(
                            "Max attempts reached [MAXLAG] after {} attempts, cumulative maxlag {}",
                            &self.max_retry_attempts, cumulative
                        )
                        .into());
                    }
                    attempts_left -= 1;
                    cumulative += lag_seconds;
                    thread::sleep(time::Duration::from_millis(1000 * lag_seconds));
                }
                None => return Ok(v),
            }
        }
    }

    /// Runs a query against the MediaWiki API, using `method` GET or POST.
    /// Parameters are a hashmap; `format=json` is enforced.
    async fn query_api_json_mut(&mut self, mut params: Params, method: Method) -> Result<Value> {
        let mut attempts_left = self.max_retry_attempts;
        params.insert("format".to_string(), "json".to_string());
        let mut cumulative: u64 = 0;
        loop {
            self.set_cumulative_maxlag_params(&mut params, method, cumulative);
            let t = self.query_api_raw_mut(&params, method).await?;
            let v: Value = serde_json::from_str(&t)?;
            match self.check_maxlag(&v) {
                Some(lag_seconds) => {
                    if attempts_left == 0 {
                        return Err(format!(
                            "Max attempts reached [MAXLAG] after {} attempts, cumulative maxlag {}",
                            &self.max_retry_attempts, cumulative
                        )
                        .into());
                    }
                    attempts_left -= 1;
                    cumulative += lag_seconds;
                    thread::sleep(time::Duration::from_millis(1000 * lag_seconds));
                }
                None => return Ok(v),
            }
        }
    }

    /// Returns the delay time after edits, in milliseconds, if set
    pub fn edit_delay(&self) -> &Option<u64> {
        &self.edit_delay_ms
    }

    /// Sets the delay time after edits in milliseconds (or `None`).
    /// This is independent of, and additional to, MAXLAG
    pub fn set_edit_delay(&mut self, edit_delay_ms: Option<u64>) {
        self.edit_delay_ms = edit_delay_ms;
    }

    /// Returns the maxlag, in seconds, if set
    pub fn maxlag(&self) -> &Option<u64> {
        &self.maxlag_seconds
    }

    /// Sets the maxlag in seconds (or `None`)
    pub fn set_maxlag(&mut self, maxlag_seconds: Option<u64>) {
        self.maxlag_seconds = maxlag_seconds;
    }

    /// Checks if a query is an edit, based on parameters and method (GET/POST)
    fn is_edit_query(&self, params: &Params, method: Method) -> bool {
        // Editing only through POST (?)
        if method != Method::Post {
            return false;
        }
        // Editing requires a token
        if !params.contains_key("token") {
            return false;
        }
        true
    }

    /// Sets the maglag parameter for a query, if necessary
    fn _set_maxlag_params(&self, params: &mut Params, method: Method) {
        if !self.is_edit_query(params, method) {
            return;
        }
        if let Some(maxlag_seconds) = self.maxlag_seconds {
            params.insert("maxlag".to_string(), maxlag_seconds.to_string());
        }
    }

    /// Sets the maglag parameter for a query, if necessary
    fn set_cumulative_maxlag_params(&self, params: &mut Params, method: Method, cumulative: u64) {
        if !self.is_edit_query(params, method) {
            return;
        }
        if let Some(maxlag_seconds) = self.maxlag_seconds {
            let added = cumulative + maxlag_seconds;
            params.insert("maxlag".to_string(), added.to_string());
        }
    }

    /// Checks for a MAGLAG error, and returns the lag if so
    fn check_maxlag(&self, v: &Value) -> Option<u64> {
        match v["error"]["code"].as_str() {
            Some(code) => match code {
                "maxlag" => v["error"]["lag"].as_u64().or(self.maxlag_seconds), // Current lag, if given, or fallback
                _ => None,
            },
            None => None,
        }
    }

    /// GET wrapper for `query_api_json`
    pub async fn get_query_api_json(&self, params: Params) -> Result<Value> {
        self.query_api_json(params, Method::Get).await
    }

    /// POST wrapper for `query_api_json`
    pub async fn post_query_api_json(&self, params: Params) -> Result<Value> {
        self.query_api_json(params, Method::Post).await
    }

    /// POST wrapper for `query_api_json`.
    /// Requires `&mut self`, for sassion cookie storage
    pub async fn post_query_api_json_mut(&mut self, params: Params) -> Result<Value> {
        self.query_api_json_mut(params, Method::Post).await
    }

    /// Adds or replaces cookies in the cookie jar from a http `Response`
    pub fn set_cookies_from_response(&mut self, resp: &reqwest::Response) {
        let cookie_strings = resp
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(ToString::to_string))
            .collect::<Vec<String>>();
        for cs in cookie_strings {
            if let Ok(cookie) = Cookie::parse(cs) {
                self.cookie_jar.add(cookie);
            }
        }
    }

    /// Generates a single string to pass as COOKIE parameter in a http `Request`
    pub fn cookies_to_string(&self) -> String {
        self.cookie_jar
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<String>>()
            .join("; ")
    }

    /// Runs a query against the MediaWiki API, and returns a text.
    /// Uses `query_raw`
    pub async fn query_api_raw(&self, params: &Params, method: Method) -> Result<String> {
        self.query_raw(&self.api_url, params, method).await
    }

    /// Runs a query against the MediaWiki API, and returns a text.
    /// Uses `query_raw_mut`
    async fn query_api_raw_mut(&mut self, params: &Params, method: Method) -> Result<String> {
        self.query_raw_mut(&self.api_url.clone(), params, method)
            .await
    }

    /// Generates a `RequestBuilder` for the API URL
    pub fn get_api_request_builder(
        &self,
        params: &Params,
        method: Method,
    ) -> Result<reqwest::RequestBuilder> {
        self.request_builder(&self.api_url, params, method)
    }

    /// Returns the user agent name
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    /// Sets the user agent name
    pub fn set_user_agent<S: Into<String>>(&mut self, agent: S) {
        self.user_agent = agent.into();
    }

    /// Returns the user agent string, as it is passed to the API through a HTTP header
    pub fn user_agent_full(&self) -> String {
        format!(
            "{}; {}-rust/{}",
            self.user_agent,
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )
    }

    /// Encodes a string
    fn rawurlencode(&self, s: &str) -> String {
        urlencoding::encode(s)
    }

    /// Signs an OAuth request
    fn sign_oauth_request(
        &self,
        method: Method,
        api_url: &str,
        to_sign: &Params,
        oauth: &OAuthParams,
    ) -> Result<String> {
        let mut keys: Vec<String> = to_sign.iter().map(|(k, _)| self.rawurlencode(k)).collect();
        keys.sort();

        let ret: Vec<String> = keys
            .into_iter()
            .filter_map(|k| match to_sign.get(&k) {
                Some(k2) => {
                    let v = self.rawurlencode(&k2);
                    Some(k + "=" + &v)
                }
                None => None,
            })
            .collect();

        let url = Url::parse(api_url)?;
        let mut url_string = url.scheme().to_owned() + "://";
        url_string += url.host_str().ok_or("url.host_str is None")?;
        if let Some(port) = url.port() {
            write!(url_string, ":{}", port).unwrap();
        }
        url_string += url.path();

        let ret = self.rawurlencode(method.as_str())
            + "&"
            + &self.rawurlencode(&url_string)
            + "&"
            + &self.rawurlencode(&ret.join("&"));

        let key: String = match (&oauth.g_consumer_secret, &oauth.g_token_secret) {
            (Some(g_consumer_secret), Some(g_token_secret)) => {
                self.rawurlencode(g_consumer_secret) + "&" + &self.rawurlencode(g_token_secret)
            }
            _ => return Err("g_consumer_secret or g_token_secret not set".into()),
        };

        let mut hmac = HmacSha1::new_varkey(&key.into_bytes())?; //crypto::hmac::Hmac::new(Sha1::new(), &key.into_bytes());
        hmac.update(&ret.into_bytes());
        let bytes = hmac.finalize().into_bytes();
        let ret: String = base64::encode(&bytes);

        Ok(ret)
    }

    /// Returns a signed OAuth POST `RequestBuilder`
    fn oauth_request_builder(
        &self,
        method: Method,
        api_url: &str,
        params: &Params,
    ) -> Result<reqwest::RequestBuilder> {
        let oauth = self
            .oauth
            .as_ref()
            .ok_or("oauth_request_builder called but self.oauth is None")?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .to_string();

        let nonce = nanoid!(10);

        let mut headers = HeaderMap::new();

        headers.insert(
            "oauth_consumer_key",
            oauth.g_consumer_key.as_ref().unwrap().parse()?,
        );
        headers.insert("oauth_token", oauth.g_token_key.as_ref().unwrap().parse()?);
        headers.insert("oauth_version", "1.0".parse()?);
        headers.insert("oauth_nonce", nonce.parse()?);
        headers.insert("oauth_timestamp", timestamp.parse()?);
        headers.insert("oauth_signature_method", "HMAC-SHA1".parse()?);

        // Prepage signing
        let mut to_sign = params.clone();
        for (key, value) in headers.iter() {
            if key == "oauth_signature" {
                continue;
            }
            to_sign.insert(key.to_string(), value.to_str()?.to_string());
        }

        headers.insert(
            "oauth_signature",
            self.sign_oauth_request(method, api_url, &to_sign, &oauth)?
                .parse()?,
        );

        // Collapse headers
        let mut header = "OAuth ".to_string();
        let parts: Vec<String> = headers
            .iter()
            .map(|(key, value)| {
                let key = key.as_str();
                let value = value.to_str().unwrap();
                self.rawurlencode(key) + "=\"" + &self.rawurlencode(value) + "\""
            })
            .collect();
        header += &parts.join(", ");

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(header.as_str())?,
        );
        headers.insert(reqwest::header::COOKIE, self.cookies_to_string().parse()?);
        headers.insert(reqwest::header::USER_AGENT, self.user_agent_full().parse()?);

        match method {
            Method::Get => Ok(self.client.get(api_url).headers(headers).query(&params)),
            Method::Post => Ok(self.client.post(api_url).headers(headers).form(&params)),
        }
    }

    /// Returns a `RequestBuilder` for a generic URL
    fn request_builder(
        &self,
        api_url: &str,
        params: &Params,
        method: Method,
    ) -> Result<reqwest::RequestBuilder> {
        // Use OAuth if set
        if self.oauth.is_some() {
            return self.oauth_request_builder(method, api_url, params);
        }

        Ok(match method {
            Method::Get => self
                .client
                .get(api_url)
                .header(reqwest::header::COOKIE, self.cookies_to_string())
                .header(reqwest::header::USER_AGENT, self.user_agent_full())
                .query(&params),
            Method::Post => self
                .client
                .post(api_url)
                .header(reqwest::header::COOKIE, self.cookies_to_string())
                .header(reqwest::header::USER_AGENT, self.user_agent_full())
                .form(&params),
        })
    }

    /// Performs a query, pauses if required, and returns the raw response
    async fn query_raw_response(
        &self,
        api_url: &str,
        params: &Params,
        method: Method,
    ) -> Result<reqwest::Response> {
        let req = self.request_builder(api_url, params, method)?;
        let resp = req.send().await?;
        self.enact_edit_delay(params, method);
        Ok(resp)
    }

    /// Delays the current thread, if the query performs an edit, and a delay time is set
    fn enact_edit_delay(&self, params: &Params, method: Method) {
        if !self.is_edit_query(params, method) {
            return;
        }
        if let Some(ms) = self.edit_delay_ms {
            thread::sleep(time::Duration::from_millis(ms));
        }
    }

    /// Runs a query against a generic URL, stores cookies, and returns a text
    /// Used for non-stateless queries, such as logins
    async fn query_raw_mut(
        &mut self,
        api_url: &str,
        params: &Params,
        method: Method,
    ) -> Result<String> {
        let resp = self.query_raw_response(api_url, params, method).await?;
        self.set_cookies_from_response(&resp);
        Ok(resp.text().await?)
    }

    /// Runs a query against a generic URL, and returns a text.
    /// Does not store cookies, but also does not require `&self` to be mutable.
    /// Used for simple queries
    pub async fn query_raw(
        &self,
        api_url: &str,
        params: &Params,
        method: Method,
    ) -> Result<String> {
        let resp = self.query_raw_response(api_url, params, method).await?;
        Ok(resp.text().await?)
    }

    /// Performs a login against the MediaWiki API.
    /// If successful, user information is stored in `User`, and in the cookie jar
    pub async fn login<S: Into<String>>(&mut self, lgname: S, lgpassword: S) -> Result<()> {
        let lgtoken = self.get_token("login").await?;
        let params = params!(
            "action" => "login",
            "lgname" => lgname,
            "lgpassword" => lgpassword,
            "lgtoken" => lgtoken,
        );
        let res = self.query_api_json_mut(params, Method::Post).await?;
        if res["login"]["result"] == "Success" {
            self.user
                .set_from_login(&res["login"])
                .map_err(String::from)?;
            self.load_current_user_info().await
        } else {
            Err("Login failed".into())
        }
    }

    /// From an API result that has a list of entries with "title" and "ns" (e.g. search), returns a vector of `Title` objects.
    pub fn result_array_to_titles(data: &Value) -> Vec<Title> {
        // See if it's the "root" of the result, then try each sub-object separately
        if data.is_object() {
            return data
                .as_object()
                .unwrap() // OK
                .iter()
                .flat_map(|(_k, v)| Api::result_array_to_titles(&v))
                .collect();
        }
        data.as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|v| Title::new_from_api_result(&v))
            .collect()
    }

    /// Performs a SPARQL query against a wikibase installation.
    /// Tries to get the SPARQL endpoint URL from the site info
    pub async fn sparql_query(&self, query: &str) -> Result<Value> {
        let query_api_url = self.get_site_info_string("general", "wikibase-sparql")?;
        let params = params!["query" => query, "format" => "json"];
        let response = self
            .query_raw_response(&query_api_url, &params, Method::Post)
            .await?;
        Ok(response.json().await?)
    }

    /// Given a `uri` (usually, an URL) that points to a Wikibase entity on this MediaWiki installation, returns the item ID
    pub fn extract_entity_from_uri(&self, uri: &str) -> Result<String> {
        let concept_base_uri = self.get_site_info_string("general", "wikibase-conceptbaseuri")?;
        if uri.starts_with(concept_base_uri) {
            Ok(uri[concept_base_uri.len()..].to_string())
        } else {
            Err(format!("{} does not start with {}", uri, concept_base_uri).into())
        }
    }

    /// Returns a vector of entity IDs (as String) from a SPARQL result, given a variable name
    pub fn entities_from_sparql_result(
        &self,
        sparql_result: &Value,
        variable_name: &str,
    ) -> Vec<String> {
        let mut entities = vec![];
        if let Some(bindings) = sparql_result["results"]["bindings"].as_array() {
            for b in bindings {
                if let Some(entity_url) = b[variable_name]["value"].as_str() {
                    entities.push(self.extract_entity_from_uri(entity_url).unwrap());
                }
            }
        }
        entities
    }

    /// Loads the user info from the API into the user structure
    pub async fn load_user_info(&self, user: &mut User) -> Result<()> {
        if !user.has_user_info() {
            let params = params![
                "action" => "query",
                "meta" => "userinfo",
                "uiprop" => "blockinfo|groups|groupmemberships|implicitgroups|rights|options|ratelimits|realname|registrationdate|unreadcount|centralids|hasmsg",
            ];
            let res = self.query_api_json(params, Method::Get).await?;
            user.set_user_info(Some(res));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Api, Title};

    #[tokio::test]
    async fn site_info() {
        let api = Api::new("https://www.wikidata.org/w/api.php")
            .await
            .unwrap();
        assert_eq!(
            api.get_site_info_string("general", "sitename").unwrap(),
            "Wikidata"
        );
        assert!(api.get_site_info_string("general", "notarealkey").is_err());
    }

    #[tokio::test]
    async fn get_token() {
        let mut api = Api::new("https://www.wikidata.org/w/api.php")
            .await
            .unwrap();
        // Token for logged out users is always the same
        assert!(!api.user.logged_in());
        assert_eq!("+\\", api.get_token("csrf").await.unwrap());
        assert_eq!("+\\", api.get_edit_token().await.unwrap());
        assert!(api.get_token("notarealtokentype").await.is_err());
    }

    #[tokio::test]
    async fn api_limit() {
        let api = Api::new("https://www.wikidata.org/w/api.php")
            .await
            .unwrap();
        let params = params!["action" => "query", "list" => "search", "srsearch" => "the"];
        let result = api
            .get_query_api_json_limit(&params, Some(20))
            .await
            .unwrap();
        assert_eq!(result["query"]["search"].as_array().unwrap().len(), 20);
    }

    #[tokio::test]
    async fn api_no_limit() {
        let api = Api::new("https://www.wikidata.org/w/api.php")
            .await
            .unwrap();
        let params = params![
            "action" => "query",
            "list" => "search",
            "srlimit" => "500",
            "srsearch" => "John haswbstatement:P31=Q5 -haswbstatement:P735",
        ];
        let result = api.get_query_api_json_all(&params).await.unwrap();
        match result["query"]["search"].as_array() {
            Some(arr) => assert!(arr.len() > 1500),
            None => panic!("result.query.search is not an array"),
        }
    }

    #[tokio::test]
    async fn sparql_query() {
        let api = Api::new("https://www.wikidata.org/w/api.php")
            .await
            .unwrap();
        let res = api.sparql_query ( "SELECT ?q ?qLabel ?fellow_id { ?q wdt:P31 wd:Q5 ; wdt:P6594 ?fellow_id . SERVICE wikibase:label { bd:serviceParam wikibase:language '[AUTO_LANGUAGE],en'. } }" ).await.unwrap() ;
        assert!(res["results"]["bindings"].as_array().unwrap().len() > 300);
    }

    #[tokio::test]
    async fn entities_from_sparql_result() {
        let api = Api::new("https://www.wikidata.org/w/api.php")
            .await
            .unwrap();
        let res = api.sparql_query ( "SELECT ?q ?qLabel ?fellow_id { ?q wdt:P31 wd:Q5 ; wdt:P6594 ?fellow_id . SERVICE wikibase:label { bd:serviceParam wikibase:language '[AUTO_LANGUAGE],en'. } } " ).await.unwrap() ;
        let titles = api.entities_from_sparql_result(&res, "q");
        assert!(titles.contains(&"Q36499535".to_string()));
    }

    #[tokio::test]
    async fn extract_entity_from_uri() {
        let api = Api::new("https://www.wikidata.org/w/api.php")
            .await
            .unwrap();
        assert_eq!(
            api.extract_entity_from_uri(&"http://www.wikidata.org/entity/Q123")
                .unwrap(),
            "Q123"
        );
        assert_eq!(
            api.extract_entity_from_uri(&"http://www.wikidata.org/entity/P456")
                .unwrap(),
            "P456"
        );
        // Expect error ('/' missing):
        assert!(api
            .extract_entity_from_uri(&"http:/www.wikidata.org/entity/Q123")
            .is_err());
    }

    #[tokio::test]
    async fn result_array_to_titles() {
        //let api = Api::new("https://www.wikidata.org/w/api.php").unwrap();
        assert_eq!(
            Api::result_array_to_titles(
                &json!({"something":[{"title":"Foo","ns":7},{"title":"Bar","ns":8},{"title":"Prefix:Baz","ns":9}]})
            ),
            vec![
                Title::new("Foo", 7),
                Title::new("Bar", 8),
                Title::new("Baz", 9)
            ]
        );
    }

    #[tokio::test]
    async fn result_namespaces() {
        let api = Api::new("https://de.wikipedia.org/w/api.php")
            .await
            .unwrap();
        assert_eq!(api.get_local_namespace_name(0), Some(""));
        assert_eq!(api.get_local_namespace_name(1), Some("Diskussion"));
        assert_eq!(api.get_canonical_namespace_name(1), Some("Talk"));
    }
}
