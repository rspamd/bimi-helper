use warp::{http::StatusCode, Reply, Rejection};
use dashmap::DashSet;
use reqwest;
use std::sync::Arc;

use crate::error::{Error};
use crate::data::*;
use crate::cert;
use log::{debug, info};

pub async fn health_handler(inflight: Arc<DashSet<String>>) -> std::result::Result<impl Reply, Rejection> {
    Ok(warp::reply::json(&HealthReply{
        requests_inflight: inflight.len()
    }))
}

pub async fn check_handler(body: RequestCert, inflight: Arc<DashSet<String>>,
                           client: reqwest::Client,
                           ca_storage: Arc<cert::CAStorage>) -> std::result::Result<impl Reply, Rejection>
{
    match reqwest::Url::parse(body.url.as_str()) {
        Ok(url) => {
            if inflight.contains(url.as_str()) {
                info!("already processing {}", body.url);
                Err(warp::reject::custom(Error::AlreadyProcessing))
            }
            else {
                info!("start processing {}; {} elements currently being processed",
                    &body.url, inflight.len());
                tokio::spawn(async move {
                    inflight.insert(body.url.clone());
                    let domain = url.domain().unwrap().to_owned();
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
                            info!("got result from {}: lenght = {}", &body.url, o.len());
                            cert::process_cert(&o, ca_storage.as_ref(),
                                               &domain);
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
            Err(warp::reject::custom(Error::BadURL(e)))
        }
    }
}