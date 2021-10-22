use serde_derive::{Serialize, Deserialize};

#[derive(Deserialize, Clone, PartialEq, Debug)]
pub struct RequestCert {
    pub url: String,
    pub redis_server: String,
}

#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct HealthReply {
    pub requests_inflight: usize,
}

