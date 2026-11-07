use std::{env, time::Duration};

use reqwest::blocking::Client;

use crate::detect::Detection;

pub struct Webhook {
    url: Option<String>,
    client: Client,
}

impl Webhook {
    pub fn from_env() -> Result<Self, reqwest::Error> {
        let url = env::var("WEBHOOK_URL").ok().filter(|value| !value.trim().is_empty());
        let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
        Ok(Self { url, client })
    }

    pub fn send(&self, detection: &Detection) -> Result<(), reqwest::Error> {
        if let Some(url) = &self.url {
            self.client.post(url).json(detection).send()?.error_for_status()?;
        }
        Ok(())
    }
}
