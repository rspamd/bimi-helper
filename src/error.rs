use thiserror::Error;
use warp::{http::StatusCode, Reply, Rejection};
use std::convert::Infallible;
use url;
use serde_derive::{Serialize};
use log::{warn, info};
use openssl::error::ErrorStack;

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
    #[error("Certificate name verification generic error")]
    CertificateGenericNameVerificationError,
    #[error("Certificate is expired")]
    CertificateExpired,
    #[error("Certificate has no valid key usage for BIMI")]
    CertificateNoKeyUsage,
    #[error("Certificate has no valid logo type for BIMI")]
    CertificateNoLogoTypeExt,
    #[error("Certificate CA is not trusted: {0}")]
    UntrustedCACert(String),
    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] ErrorStack),
}

impl warp::reject::Reject for AppError {}

#[derive(Serialize)]
struct ErrorResponse {
    pub message: String,
}


pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if let Some(_) = err.find::<warp::filters::body::BodyDeserializeError>() {
        code = StatusCode::BAD_REQUEST;
        message = "Invalid Body";
    } else if let Some(e) = err.find::<AppError>() {
        match e {
            AppError::AlreadyProcessing => {
                code = StatusCode::NOT_MODIFIED;
                message = "Already processing";
            },
            AppError::BadURL(e) => {
                info!("bad url requested: {}", e);
                code = StatusCode::BAD_REQUEST;
                message = "Invalid URL";
            },
            _ => {
                warn!("unhandled application error: {:?}", err);
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = "Internal Server Error";
            }
        }
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Method Not Allowed";
    } else {
        warn!("unhandled error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    let json = warp::reply::json(&ErrorResponse {
        message: message.into(),
    });

    Ok(warp::reply::with_status(json, code))
}