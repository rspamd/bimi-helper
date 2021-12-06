extern crate redis;
use self::redis::AsyncCommands;
use crate::data::RequestSVG;
use crate::error::AppError;
use std::time::Duration;
use structopt::StructOpt;
use tokio::time::timeout;

#[derive(Debug, StructOpt, Clone)]
pub struct RedisStorageConfig {
    /// Redis operations timeout
    #[structopt(long = "redis-timeout", default_value = "5.0")]
    timeout: f32,
    #[structopt(long = "redis-expiry", default_value = "259200")]
    expiry: f32,
    /// Prefix for Redis keys (if not specified in a request)
    #[structopt(long = "redis-prefix")]
    prefix: Option<String>,
}

pub struct RedisStorage {
    config: RedisStorageConfig,
}

impl RedisStorage {
    pub fn new(cfg: RedisStorageConfig) -> Self {
        Self { config: cfg }
    }

    pub async fn store_result<T>(
        &self,
        req: &RequestSVG,
        key: &str,
        data: T,
    ) -> Result<(), AppError>
    where
        T: redis::ToRedisArgs + Send + Sync,
    {
        let client = redis::Client::open(req.redis_server.as_deref().unwrap())?;
        let mut conn = client.get_async_connection().await?;
        let expiry = req
            .redis_expiry
            .unwrap_or((self.config.expiry * 1000.0) as usize);

        let prefix = req
            .redis_prefix
            .as_deref()
            .unwrap_or_else(|| self.config.prefix.as_deref().unwrap_or(""));
        let real_key = prefix.to_string() + key;

        let cmd_fut = async {
            conn.pset_ex(real_key, data, expiry).await?;
            Ok::<(), redis::RedisError>(())
        };
        match timeout(Duration::from_secs_f32(self.config.timeout), cmd_fut).await {
            Ok(res) => match res {
                Ok(_) => Ok(()),
                Err(e) => Err(AppError::RedisError(e)),
            },
            Err(e) => Err(AppError::IOTimeoutError(e)),
        }?;

        Ok(())
    }
}
