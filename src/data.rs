use serde_derive::{Serialize, Deserialize};

#[derive(Deserialize, Clone, PartialEq, Debug)]
pub struct RequestCert {
    /// Url where certificate is placed
    pub url: String,
    /// Domain to match certificate
    pub domain: String,
    /// Redis server to store results
    pub redis_server: String,
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

