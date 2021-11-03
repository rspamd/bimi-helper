use warp::{http::StatusCode, Reply, Rejection};
use dashmap::DashSet;
use url::Url;
use reqwest;
use std::sync::Arc;
use serde_json;
use base64;
use bytes::Bytes;

use crate::error::{AppError};
use crate::data::*;
use crate::{cert, mini_pki, redis_storage};
use log::{info, warn};

// The file size of SVG Tiny PS documents SHOULD be as small as
// possible, and SHOULD NOT exceed 32 kilobytes.  That size should be
// evaluated when the document is uncompressed.
const MAX_SVG_SIZE : usize = 32 * 1024;

pub async fn health_handler(inflight: Arc<DashSet<String>>) -> Result<impl Reply, Rejection> {
    Ok(warp::reply::json(&HealthReply{
        requests_inflight: inflight.len()
    }))
}

pub async fn check_handler(body: RequestCert, inflight: Arc<DashSet<String>>,
                           client: reqwest::Client,
                           ca_storage: Arc<mini_pki::CAStorage>,
                           redis_storage: Arc<redis_storage::RedisStorage>)
                           -> Result<Box<dyn warp::Reply>, Rejection>
{
    match reqwest::Url::parse(body.url.as_str()) {
        Ok(url) => {
            handle_request(body, inflight, client, url, redis_storage,
                           move |o, req| {
                let domain = &req.domain;
                info!("got result from {}: length = {}", &req.url, o.len());
                let result = match cert::process_cert(&o,
                                                      ca_storage.as_ref(),
                                                      &domain) {
                    Err(e) => {
                        info!("cannot process cert for {}: {:?}", domain, e);
                        serde_json::to_string(&RetreiveError{
                            error: e.to_string().as_str()
                        }).unwrap()
                    }
                    Ok(svg_bytes) => {
                        info!("processed certificate for {}", domain);
                        let encoded = base64::encode(svg_bytes);
                        serde_json::to_string(&SvgResult{
                            content: encoded.as_str()
                        }).unwrap()
                    }
                };
                Ok(result)
            }).await
        }
        Err(e) => {
            Err(warp::reject::custom(AppError::BadURL(e)))
        }
    }
}

pub async fn svg_handler(body: RequestCert, inflight: Arc<DashSet<String>>,
                           client: reqwest::Client,
                           redis_storage: Arc<redis_storage::RedisStorage>)
                           -> Result<Box<dyn warp::Reply>, Rejection>
{
    match reqwest::Url::parse(body.url.as_str()) {
        Ok(url) => {
            handle_request(body, inflight, client, url, redis_storage,
                           move |o, req| {
                info!("got SVG result from {}: length = {}", &req.url, o.len());
                Ok(o.to_vec())
            }).await
        }
        Err(e) => {
            Err(warp::reject::custom(AppError::BadURL(e)))
        }
    }
}

async fn handle_request<T, F>(body: RequestCert,
                        inflight: Arc<DashSet<String>>,
                        client: reqwest::Client,
                        url: Url,
                        redis_storage: Arc<redis_storage::RedisStorage>,
                        check_f: F) -> Result<Box<dyn warp::Reply>, Rejection>
    where F: FnOnce(Bytes, &RequestCert) -> Result<T, Rejection> + Send + 'static,
          T: Send + Sync + redis::ToRedisArgs + warp::Reply + 'static
{
    if inflight.contains(url.as_str()) {
        info!("already processing {}", body.url);
        Err(warp::reject::custom(AppError::AlreadyProcessing))
    }
    else {
        info!("start processing {}; {} elements currently being processed",
                    &body.url, inflight.len());
        let is_sync = body.sync.unwrap_or(false);
        let fut = tokio::spawn(async move {
            inflight.insert(body.url.clone());
            let domain = &body.domain;
            let req = client.get(url).send();
            let resp = match req.await {
                Ok(o) => {
                    o.bytes()
                }
                Err(e) => {
                    info!("cannot get send request to {}: {}", &body.url, e);
                    inflight.remove(&body.url);
                    return Err(AppError::HTTPClientError(e));
                }
            };
            match resp.await {
                Ok(o) => {
                    inflight.remove(&body.url);
                    check_svg_size(&o)?;
                    let res = check_f(o, &body).unwrap();
                    redis_storage.store_result(&body.redis_server,
                                               domain.as_str(),
                                               &res)
                        .await
                        .unwrap_or_else(|e| {
                            warn!("cannot store results for domain {} to redis: {:?}",
                                        domain.as_str(), e);
                        });
                    Ok(res)
                }
                Err(e) => {
                    info!("cannot get results from {}: {}", &body.url, e);
                    inflight.remove(&body.url);
                    Err(AppError::HTTPClientError(e))
                }
            }
        });
        if is_sync {
            match fut.await.map_err(|e| AppError::JoinError(e))? {
                Ok(res) => Ok(Box::new(warp::reply::with_status(res, StatusCode::OK))),
                Err(e) => Err(warp::reject::custom(e))
            }

        }
        else {
            // We do not await this future as the idea is to perform
            // all those lookups asynchronously
            Ok(Box::new(StatusCode::OK))
        }
    }
}

// Checks SVG size according to IETF recommendation (should happen after decompression)
fn check_svg_size(input : &Bytes) -> Result<(), AppError>
{
    let sz = input.len();
    if (sz > MAX_SVG_SIZE) || sz < 8 {
        Err(AppError::SVGSizeError(sz))
    }
    else {
        Ok(())
    }
}