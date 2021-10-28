use warp::{http::StatusCode, Reply, Rejection};
use dashmap::DashSet;
use reqwest;
use std::sync::Arc;
use serde_json;
use base64;

use crate::error::{AppError};
use crate::data::*;
use crate::{cert, mini_pki, redis_storage};
use log::{debug, info};

pub async fn health_handler(inflight: Arc<DashSet<String>>) -> std::result::Result<impl Reply, Rejection> {
    Ok(warp::reply::json(&HealthReply{
        requests_inflight: inflight.len()
    }))
}

pub async fn check_handler(body: RequestCert, inflight: Arc<DashSet<String>>,
                           client: reqwest::Client,
                           ca_storage: Arc<mini_pki::CAStorage>,
                           redis_storage: Arc<redis_storage::RedisStorage>)
                           -> std::result::Result<impl Reply, Rejection>
{
    match reqwest::Url::parse(body.url.as_str()) {
        Ok(url) => {
            if inflight.contains(url.as_str()) {
                info!("already processing {}", body.url);
                Err(warp::reject::custom(AppError::AlreadyProcessing))
            }
            else {
                info!("start processing {}; {} elements currently being processed",
                    &body.url, inflight.len());
                tokio::spawn(async move {
                    inflight.insert(body.url.clone());
                    let domain = body.domain;
                    let req = client.get(url).send();
                    let resp = match req.await {
                        Ok(o) => {
                            o.bytes()
                        }
                        Err(e) => {
                            info!("cannot get send request to {}: {}", &body.url, e);
                            inflight.remove(&body.url);
                            return Err(e);
                        }
                    };
                    match resp.await {
                        Ok(o) => {
                            info!("got result from {}: length = {}", &body.url, o.len());
                            match cert::process_cert(&o, ca_storage.as_ref(),
                                               &domain) {
                                Err(e) => {
                                    info!("cannot process cert for {}: {:?}", domain, e);
                                    redis_storage.store_result(&body.redis_server,
                                                               domain.as_str(),
                                                               serde_json::to_string(&RetreiveError{
                                                                   error: e.to_string().as_str()
                                                               }).unwrap().as_str())
                                        .await;
                                }
                                Ok(svg_bytes) => {
                                    info!("processed certificate for {}", domain);
                                    let encoded = base64::encode(svg_bytes);
                                    redis_storage.store_result(&body.redis_server,
                                                               domain.as_str(),
                                                               serde_json::to_string(&SvgResult{
                                                                   content: encoded.as_str()
                                                               }).unwrap().as_str())
                                        .await;
                                }
                            }
                            inflight.remove(&body.url);
                            Ok(())
                        }
                        Err(e) => {
                            info!("cannot get results from {}: {}", &body.url, e);
                            inflight.remove(&body.url);
                            Err(e)
                        }
                    }
                });
                Ok(StatusCode::OK)
            }
        }
        Err(e) => {
            Err(warp::reject::custom(AppError::BadURL(e)))
        }
    }
}