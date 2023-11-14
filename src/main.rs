use log::info;
use log::LevelFilter;

extern crate openssl_sys as openssl_ffi;
extern crate foreign_types;
#[macro_use]
extern crate lazy_static;

use clap::{Parser, ArgAction};
use dashmap::DashSet;
use std::{
    convert::Infallible,
    fs::{self, File},
    io::{self, BufRead},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use warp::Filter;

mod cert;
mod data;
mod error;
mod handler;
mod mini_pki;
mod redis_storage;
mod svg;
mod x509_helpers;

use crate::error::AppError;
use redis_storage::RedisStorage;

#[cfg(all(unix, feature = "drop_privs"))]
use privdrop::PrivDrop;

#[derive(Debug, Parser, Clone)]
#[clap(
    name = "bimi-agent",
    about = "BIMI agent to assist images verification end extraction",
    author,
    version,
    rename_all = "kebab-case"
)]
struct Config {
    /// Listen address to bind to
    #[clap(short = 'l', long = "listen", default_value = "0.0.0.0:3030")]
    listen_addr: SocketAddr,
    /// Verbose level (repeat for more verbosity)
    #[clap(short = 'v', action = ArgAction::Count)]
    verbose: u8,
    #[clap(flatten)]
    #[cfg(all(unix, feature = "drop_privs"))]
    privdrop: PrivDropConfig,
    #[clap(long = "privkey", value_parser)]
    /// Private key for SSL HTTP server
    privkey: Option<PathBuf>,
    /// X509 certificate for HTTP server
    #[clap(long = "cert", value_parser)]
    cert: Option<PathBuf>,
    /// Number of threads to start
    #[clap(short = 'n', default_value = "2")]
    max_threads: usize,
    /// HTTP client timeout
    #[clap(short = 't', long = "timeout", default_value = "5.0")]
    http_timeout: f32,
    /// HTTP user agent
    #[clap(short = 'U', long = "user-agent", default_value = "BIMI-Agent/0.1")]
    http_ua: String,
    /// Trusted fingerprint
    #[clap(short = 'F', long = "fingerprint")]
    fingerprints: Option<Vec<String>>,
    /// Trusted fingerprints file
    #[clap(long)]
    fingerprints_file: Option<String>,
    /// Trusted SSL root in PEM format
    #[clap(long)]
    ssl_ca_file: Option<Vec<String>>,
    #[clap(flatten)]
    redis_conf: redis_storage::RedisStorageConfig,
}

#[cfg(all(unix, feature = "drop_privs"))]
#[derive(Debug, Parser, Clone, Default)]
#[clap(rename_all = "kebab-case")]
struct PrivDropConfig {
    /// Run as this user and their primary group
    #[clap(short = 'u', long)]
    user: Option<String>,
    /// Run as this group
    #[clap(short = 'g', long)]
    group: Option<String>,
    /// Chroot to this directory
    #[clap(long)]
    chroot: Option<String>,
}

fn drop_privs(privdrop: &PrivDropConfig) {
    #[cfg(all(unix, feature = "drop_privs"))]
    let privdrop_enabled = [&privdrop.chroot, &privdrop.user, &privdrop.group]
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

fn with_dash_set(
    set: SharedSet,
) -> impl Filter<Extract = (SharedSet,), Error = Infallible> + Clone {
    warp::any().map(move || set.clone())
}

fn with_http_client(
    client: reqwest::Client,
) -> impl Filter<Extract = (reqwest::Client,), Error = Infallible> + Clone {
    warp::any().map(move || client.clone())
}

fn with_cert_storage(
    storage: Arc<mini_pki::CAStorage>,
) -> impl Filter<Extract = (Arc<mini_pki::CAStorage>,), Error = Infallible> + Clone {
    warp::any().map(move || storage.clone())
}

fn with_redis_storage(
    storage: Arc<redis_storage::RedisStorage>,
) -> impl Filter<Extract = (Arc<redis_storage::RedisStorage>,), Error = Infallible> + Clone {
    warp::any().map(move || storage.clone())
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() -> Result<(), AppError> {
    let opts = Config::parse();
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
    let domains_inflight: SharedSet = Arc::new(DashSet::with_capacity(128));

    // Create CA storage and add trusted fingerprints
    let ca_storage = Arc::new(mini_pki::CAStorage::new().unwrap());
    if let Some(ref fp_vec) = opts.fingerprints {
        for fp in fp_vec.iter() {
            ca_storage.as_ref().add_fingerprint(fp.as_str())?;
        }
    }
    if let Some(ref fname) = opts.fingerprints_file {
        if let Ok(lines) = read_lines(fname) {
            for ln in lines.flatten() {
                ca_storage.as_ref().add_fingerprint(ln.trim())?;
            }
        }
    }
    if let Some(ref fnames) = opts.ssl_ca_file {
        for fname in fnames {
            ca_storage.as_ref().add_ca_pem(fname)?;
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
                let privkey = fs::read(opts.privkey.unwrap()).expect("cannot read privkey file");
                let cert = fs::read(opts.cert.unwrap()).expect("cannot read privkey file");
                // Drop privs after keys are read
                drop_privs(&opts.privdrop);

                server
                    .tls()
                    .cert(cert)
                    .key(privkey)
                    .run(opts.listen_addr)
                    .await;
            } else {
                drop_privs(&opts.privdrop);
                server.run(opts.listen_addr).await;
            }
        });
    Ok(())
}
