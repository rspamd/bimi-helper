use thiserror::Error;
use warp::{http::StatusCode, reject, Reply, Rejection};
use std::convert::Infallible;
use url;
use serde_derive::{Serialize};
use log::{warn, info};

#[derive(Error, Debug)]
pub enum Error {
    #[error("error reading file: {0}")]
    ReadFileError(#[from] std::io::Error),
    #[error("already processing")]
    AlreadyProcessing,
    #[error("invalid url")]
    BadURL(#[from] url::ParseError),
}

impl warp::reject::Reject for Error {}

#[derive(Serialize)]
struct ErrorResponse {
    pub message: String,
}

type Result<T> = std::result::Result<T, warp::Rejection>;
pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if let Some(_) = err.find::<warp::filters::body::BodyDeserializeError>() {
        code = StatusCode::BAD_REQUEST;
        message = "Invalid Body";
    } else if let Some(e) = err.find::<Error>() {
        match e {
            Error::AlreadyProcessing => {
                code = StatusCode::NOT_MODIFIED;
                message = "Already processing";
            },
            Error::BadURL(e) => {
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