use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;

use super::server::ServerContext;

pub(crate) mod context;

pub use context::{IpData, UpdateData, UserRaw};
use context::{Request, UpdateResponse, UserFetchResponse};

pub struct Client {
    pub id: usize,
    pub base_url: String,
    pub key: String,

    pub duration: Duration,

    inner: reqwest::Client,
    server: Arc<ServerContext>,

    running: HashMap<usize, UserRaw>,
}

impl Client {
    #[inline]
    pub fn new(server: Arc<ServerContext>) -> Self {
        let inner = reqwest::ClientBuilder::new().user_agent("TrojanX/0.0.5")
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        Client {
            id: 0,
            inner,
            server,
            base_url: String::new(),
            key: String::new(),
            duration: Duration::from_secs(90),
            running: HashMap::new(),
        }
    }

    pub async fn run(mut self) {
        loop {
            if let Err(e) = self.fetch_users().await {
                log::error!("failed to fetch user: {}", e);
            }

            sleep(self.duration).await;

            if let Err(e) = self.update_traffic().await {
                log::error!("failed to update user traffic: {}", e);
            }
            if let Err(e) = self.upload_ip().await {
                log::error!("failed to upload user ip: {}", e);
            }
        }
    }

    async fn fetch_users(&mut self) -> Result<(), reqwest::Error> {
        let url = self.build_url("/users");
        let res = self.inner.get(url).send().await?;

        let res: UserFetchResponse = res.json().await?;
        let fetch_users: HashMap<usize, UserRaw> = res.data.into_iter().map(|u| (u.id, u)).collect();

        let mut users = self.server.users.write().unwrap();

        // remove user not present in fetch_users
        for (id, user) in self.running.iter() {
            if fetch_users.get(id).is_none() {
                users.remove(&user.pwd);
            }
        }

        for (id, user) in fetch_users.iter() {
            match self.running.get(id) {
                Some(u) => {
                    if user != u {
                        // reload user changed

                        if let Some(ctx) = users.get(&user.pwd) {
                            // user ctx changed
                            user.update_ctx(ctx);
                        } else if let Some(ctx) = users.remove(&u.pwd) {
                            // user pwd changed: remove, update ctx, re-insert
                            user.update_ctx(&ctx);
                            users.insert(user.pwd, ctx);
                        }
                    }
                }
                None => {
                    // add user not present in running
                    let (p, u) = user.as_server_user();
                    users.insert(p, u);
                }
            }
        }
        self.running = fetch_users;

        log::info!("user fetched, now: {}", self.running.len());
        Ok(())
    }

    pub async fn update_traffic(&self) -> Result<(), reqwest::Error> {
        let url = self.build_url("/users/traffic");
        let data = self.server.collect_update();
        if data.is_empty() {
            // nothing to update, just return
            return Ok(());
        }
        let res = self.inner.post(url).json(&Request { data: &data }).send().await?;
        let res: UpdateResponse = res.json().await?;

        if res.status == 1 {
            self.server.assume_update(&data);
            log::info!("{} users update", data.len());
        } else {
            log::error!("failed to update user: error #{}", res.status);
        }
        Ok(())
    }

    pub async fn upload_ip(&self) -> Result<(), reqwest::Error> {
        let url = self.build_url("/users/aliveip");

        let data = self.server.collect_ip();
        if data.is_empty() {
            // nothing to update, just return
            return Ok(());
        }
        let res = self.inner.post(url).json(&Request { data: &data }).send().await?;
        let res: UpdateResponse = res.json().await?;
        if res.status == 1 {
            log::info!("{} users uploaded", data.len());
        } else {
            log::error!("failed to upload ip: error #{}", res.status);
        }
        Ok(())
    }

    fn build_url<S: AsRef<str>>(&self, path: S) -> String {
        let mut url = self.base_url.clone();
        url.push_str(path.as_ref());
        url.push('?');

        let mut serializer = form_urlencoded::Serializer::new(String::new());
        serializer.extend_pairs([("node_id", &self.id.to_string()), ("key", &self.key)]);
        url.push_str(&serializer.finish());
        url
    }
}
