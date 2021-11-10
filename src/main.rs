#[macro_use]
extern crate lazy_static;
extern crate openssl_sys as openssl_ffi;
#[macro_use]
extern crate foreign_types;

use log::LevelFilter;
use log::{info};

use std::net::SocketAddr;
use structopt::StructOpt;
use reqwest;
use warp::{Filter};
use std::fs;
use dashmap::DashSet;
use std::sync::Arc;
use std::convert::Infallible;
use std::time::Duration;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::{PathBuf, Path};

mod handler;
mod error;
mod data;
mod cert;
mod mini_pki;
mod x509_helpers;
mod redis_storage;
mod svg;

use redis_storage::RedisStorage;
use crate::error::AppError;

#[cfg(all(unix, feature = "drop_privs"))]
use privdrop::PrivDrop;

#[derive(Debug, StructOpt)]
#[structopt(name = "bimi-agent", about = "BIMI agent to assist images verification end extraction")]
struct Config {
    /// Listen address to bind to
    #[structopt(short = "l", long = "listen", default_value = "0.0.0.0:3030")]
    listen_addr: SocketAddr,
    /// Verbose level (repeat for more verbosity)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: u8,
    #[structopt(flatten)]
    #[cfg(all(unix, feature = "drop_privs"))]
    privdrop: PrivDropConfig,
    #[structopt(long = "privkey", parse(from_os_str))]
    /// Private key for SSL HTTP server
    privkey: Option<PathBuf>,
    /// X509 certificate for HTTP server
    #[structopt(long = "cert", parse(from_os_str))]
    #[structopt(parse(from_os_str))]
    cert: Option<PathBuf>,
    /// Number of threads to start
    #[structopt(short = "n", long = "max-threads", default_value = "2")]
    max_threads: usize,
    /// HTTP client timeout
    #[structopt(short = "t", long = "timeout", default_value = "5.0")]
    http_timeout: f32,
    /// HTTP user agent
    #[structopt(short = "U", long = "user-agent", default_value = "BIMI-Agent/0.1")]
    http_ua: String,
    /// Trusted fingerprint
    #[structopt(short = "F", long = "fingerprint")]
    fingerprints: Option<Vec<String>>,
    /// Trusted fingerprints file
    #[structopt(long = "fingerprints-file")]
    fingerprints_file: Option<String>,
    #[structopt(flatten)]
    redis_conf : redis_storage::RedisStorageConfig,
}

#[cfg(all(unix, feature = "drop_privs"))]
#[derive(Debug, StructOpt)]
struct PrivDropConfig {
    /// Run as this user and their primary group
    #[structopt(short = "u", long = "user")]
    user: Option<String>,
    /// Run as this group
    #[structopt(short = "g", long = "group")]
    group: Option<String>,
    /// Chroot to this directory
    #[structopt(long = "chroot")]
    chroot: Option<String>,
}

fn drop_privs(privdrop: &PrivDropConfig) {
    #[cfg(all(unix, feature = "drop_privs"))]
    let privdrop_enabled = [
            &privdrop.chroot,
            &privdrop.user,
            &privdrop.group]
            .iter()
            .any(|o| o.is_some());
    if privdrop_enabled {
        let mut pd = PrivDrop::default();
        if let Some(path) = &privdrop.chroot {
            info!("chroot: {}", path);
            pd = pd.chroot(path);
        }

        if let Some(user) = &privdrop.user {
            info!("setuid user: {}", user);
            pd = pd.user(user);
        }

        if let Some(group) = &privdrop.group {
            info!("setgid group: {}", group);
            pd = pd.group(group);
        }

        pd.apply()
            .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));

        info!("dropped privs");
    }
}

type SharedSet = Arc<DashSet<String>>;

fn with_dash_set(set: SharedSet)
    -> impl Filter<Extract = (SharedSet,), Error = Infallible> + Clone {
    warp::any().map(move || set.clone())
}

fn with_http_client(client: reqwest::Client)
    -> impl Filter<Extract = (reqwest::Client,), Error = Infallible> + Clone {
    warp::any().map(move || client.clone())
}

fn with_cert_storage(storage: Arc<mini_pki::CAStorage>)
    -> impl Filter<Extract = (Arc<mini_pki::CAStorage>,), Error = Infallible> + Clone {
    warp::any().map(move || storage.clone())
}

fn with_redis_storage(storage: Arc<redis_storage::RedisStorage>)
    -> impl Filter<Extract = (Arc<redis_storage::RedisStorage>,), Error = Infallible> + Clone {
    warp::any().map(move || storage.clone())
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}


fn main()  -> Result<(), AppError> {
    let opts = Config::from_args();
    let has_sane_tls = opts.privkey.is_some() && opts.cert.is_some();
    let log_level = match opts.verbose {
        0 => LevelFilter::Off,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs_f32(opts.http_timeout))
        .user_agent(&opts.http_ua)
        .build()
        .expect("cannot build HTTP client");

    env_logger::Builder::from_default_env()
        .filter(None, log_level)
        .format_timestamp(Some(env_logger::fmt::TimestampPrecision::Millis))
        .init();
    let domains_inflight : SharedSet =
        Arc::new(DashSet::with_capacity(128));

    // Create CA storage and add trusted fingerprints
    let ca_storage = Arc::new(mini_pki::CAStorage::new().unwrap());
    if let Some(ref fp_vec) = opts.fingerprints {
        for fp in fp_vec.iter() {
            ca_storage.as_ref().add_fingerprint(fp.as_str())?;
        }
    }
    if let Some(ref fname) = opts.fingerprints_file {
        if let Ok(lines) = read_lines(fname) {
            for ln in lines {
                if let Ok(fp) = ln {
                    ca_storage.as_ref().add_fingerprint(fp.trim())?;
                }
            }
        }
    }

    let redis_storage = Arc::new(RedisStorage::new(opts.redis_conf.clone()));

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(opts.max_threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let health_route = warp::path!("v1" / "health")
                .and(with_dash_set(domains_inflight.clone()))
                .and_then(handler::health_handler);
            // Path to verify VMC
            let check_route = warp::path!("v1" / "check")
                .and(warp::post())
                .and(warp::body::json())
                .and(with_dash_set(domains_inflight.clone()))
                .and(with_http_client(http_client.clone()))
                .and(with_cert_storage(ca_storage.clone()))
                .and(with_redis_storage(redis_storage.clone()))
                .and_then(handler::check_handler);
            // Path to download SVG only
            let svg_route = warp::path!("v1" / "svg")
                .and(warp::post())
                .and(warp::body::json())
                .and(with_dash_set(domains_inflight.clone()))
                .and(with_http_client(http_client.clone()))
                .and(with_redis_storage(redis_storage.clone()))
                .and_then(handler::svg_handler);
            let routes = health_route
                .or(check_route)
                .or(svg_route)
                .with(warp::cors().allow_any_origin())
                .recover(error::handle_rejection);

            let server = warp::serve(routes);

            if has_sane_tls {
                let privkey = fs::read(opts.privkey.unwrap())
                    .expect("cannot read privkey file");
                let cert = fs::read(opts.cert.unwrap())
                    .expect("cannot read privkey file");
                // Drop privs after keys are read
                drop_privs(&opts.privdrop);

                server.tls()
                    .cert(cert)
                    .key(privkey)
                    .run(opts.listen_addr)
                    .await;
            } else {
                drop_privs(&opts.privdrop);
                server.run(opts.listen_addr)
                    .await;
            }
        });
    Ok(())
}

