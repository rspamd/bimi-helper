extern crate redis;
use structopt::StructOpt;
use self::redis::{AsyncCommands};
use tokio::time::timeout;
use std::time::Duration;
use crate::error::{AppError};

#[derive(Debug, StructOpt, Clone)]
pub struct RedisStorageConfig {
    /// Redis operations timeout
    #[structopt(long = "redis-timeout", default_value = "5.0")]
    timeout : f32,
    #[structopt(long = "redis-expiry", default_value = "259200")]
    expiry: f32,
    /// Prefix for Redis keys (if not specified in a request)
    #[structopt(long = "redis-prefix")]
    prefix: Option<String>
}

pub struct RedisStorage {
    config: RedisStorageConfig,
}

impl RedisStorage {
    pub fn new(cfg: RedisStorageConfig) -> Self {
        Self {
            config: cfg,
        }
    }

    pub async fn store_result(&self, server : &str, key : &str, data : &[u8])
        -> Result<(), AppError>
    {
        let client = redis::Client::open(server)?;
        let mut conn = client.get_async_connection().await?;
        let expiry = (self.config.expiry * 1000.0) as usize;

        let real_key = match &self.config.prefix {
            Some(prefix) => {
                String::from(prefix) + key
            }
            None => {
                key.to_string()
            }
        };

        let cmd_fut = async {
            conn.pset_ex(real_key, data, expiry).await?;
            Ok::<(), redis::RedisError>(())
        };
        match timeout(Duration::from_secs_f32(self.config.timeout),
                cmd_fut).await {
            Ok(res) => {
                match res {
                    Ok(_) => Ok(()),
                    Err(e) => Err(AppError::RedisError(e))
                }
            }
            Err(e) => {
                Err(AppError::IOTimeoutError(e))
            }
        }?;

        Ok(())
    }
}