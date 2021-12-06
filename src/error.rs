use log::{info, warn};
use openssl::error::ErrorStack;
use redis::RedisError;
use serde_derive::Serialize;
use std::convert::Infallible;
use thiserror::Error;
use tokio::task::JoinError;
use tokio::time::error::Elapsed;
use warp::{http::StatusCode, Rejection, Reply};

#[derive(Error, Debug)]
pub enum AppError {
    #[error("error reading file: {0}")]
    ReadFileError(#[from] std::io::Error),
    #[error("already processing")]
    AlreadyProcessing,
    #[error("invalid url")]
    BadURL(#[from] url::ParseError),
    #[error("bad pem certificate")]
    BadPEM,
    #[error("x509 parse error: {0}")]
    CertificateParseError(String),
    #[error("CA init error: {0}")]
    CAInitError(String),
    #[error("Invalid time: {0}")]
    TimeParseError(#[from] chrono::ParseError),
    #[error("Certificate CA verification error: {0}")]
    CertificateVerificationError(String),
    #[error("Certificate name verification error: {0}")]
    CertificateNameVerificationError(String),
    #[error("Certificate is expired")]
    CertificateExpired,
    #[error("Certificate has no valid key usage for BIMI")]
    CertificateNoKeyUsage,
    #[error("Certificate has no valid logo type for BIMI")]
    CertificateNoLogoTypeExt,
    #[error("Certificate has no valid logo url")]
    CertificateInvalidLogoURL,
    #[error("Certificate CA is not trusted: {0}")]
    UntrustedCACert(String),
    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] ErrorStack),
    #[error("Redis error: {0}")]
    RedisError(#[from] RedisError),
    #[error("IO timeout")]
    IOTimeoutError(#[from] Elapsed),
    #[error("Invalid trusted fingerprint (must be hex of sha256)")]
    InvalidFingerprint,
    #[error("Future handling error")]
    JoinError(#[from] JoinError),
    #[error("HTTP client error")]
    HTTPClientError(#[from] reqwest::Error),
    #[error("Invalid SVG size")]
    SVGSizeError(usize),
    #[error("ASN.1 parse error")]
    ASN1Error(#[from] nom::Err<der_parser::error::BerError>),
    #[error("BER type error")]
    BERError(#[from] der_parser::error::BerError),
}

impl warp::reject::Reject for AppError {}

#[derive(Serialize)]
struct ErrorResponse {
    pub error: String,
}

pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let code;
    let message;
    let message_str: String;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if err
        .find::<warp::filters::body::BodyDeserializeError>()
        .is_some()
    {
        code = StatusCode::BAD_REQUEST;
        message = "Invalid Body";
    } else if let Some(e) = err.find::<AppError>() {
        match e {
            AppError::AlreadyProcessing => {
                code = StatusCode::NOT_MODIFIED;
                message = "Already processing";
            }
            AppError::BadURL(e) => {
                info!("bad url requested: {}", e);
                code = StatusCode::BAD_REQUEST;
                message = "Invalid URL";
            }
            _ => {
                warn!("unhandled application error: {:?}", err);
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message_str = e.to_string();
                message = message_str.as_str();
            }
        }
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Method Not Allowed";
    } else {
        warn!("unhandled error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    let json = warp::reply::json(&ErrorResponse {
        error: message.into(),
    });

    Ok(warp::reply::with_status(json, code))
}
