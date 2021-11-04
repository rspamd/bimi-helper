use serde_derive::{Serialize, Deserialize};

#[derive(Deserialize, Clone, PartialEq, Debug)]
pub struct RequestSVG {
    /// Url where certificate/svg is placed
    pub url: String,
    /// Domain to match certificate
    pub domain: String,
    /// Redis server to store results
    pub redis_server: Option<String>,
    /// Whether a client wants reply immediately
    pub sync: Option<bool>,
    /// Custom expiration for this request
    pub redis_expiry: Option<usize>,
    /// Custom redis prefix for this request
    pub redis_prefix: Option<String>,
    /// Skip Redis completely
    pub skip_redis: Option<bool>
}

#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct HealthReply {
    /// How many requests are now pending
    pub requests_inflight: usize,
}

#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct SvgResult<'a> {
    /// SVG image raw data
    pub content: &'a str,
}

#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct RetreiveError<'a> {
    /// Error to store
    pub error: &'a str,
}

