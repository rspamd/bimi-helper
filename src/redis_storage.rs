extern crate redis;
use structopt::StructOpt;
use self::redis::AsyncCommands;

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

    pub async fn store_result(&self, server : &str, key : &str, data : &str)
        -> Result<(), redis::RedisError>
    {
        let client = redis::Client::open(server)?;
        let mut conn = client.get_async_connection().await?;
        match &self.config.prefix {
            Some(prefix) => {
                let prefixed_key = String::from(prefix) + key;
                conn.pset_ex(prefixed_key, data, (self.config.expiry * 1000.0) as usize)
                    .await?;
            }
            None => {
                conn.pset_ex(key, data, (self.config.expiry * 1000.0) as usize)
                    .await?;
            }
        }
        Ok(())
    }
}