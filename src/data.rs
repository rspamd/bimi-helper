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
    pub requests_inflight: usize,
}

