use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum SecretKey {
    Seed { seed: String },
    Key { key: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Log level. See `<https://docs.rs/log/0.4.17/log/enum.LevelFilter.html>` for possible log level values. (default: `INFO`)
    pub log_level: String,
    /// Set to display structured logs in JSON format. Otherwise, plain text format is used. (default: false)
    pub log_format_json: bool,
    /// Secret key for used to generate keypair. Can be either set to `seed` or to `key`.
    /// If set to seed, keypair will be generated from that seed.
    /// If set to key, a valid ed25519 private key must be provided, else the client will fail
    /// If `secret_key` is not set, random seed will be used.
    pub secret_key: Option<SecretKey>,
    /// Sets the listening P2P network service port. (default: 37000)
    pub p2p_port: u16,
    /// Sets application-specific version of the protocol family used by the peer. (default: "/avail_kad/id/1.0.0")
    pub identify_protocol: String,
    /// Sets agent version that is sent to peers in the network. (default: "avail-light-client/rust-client")
    pub identify_agent: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            log_level: "INFO".to_string(),
            log_format_json: false,
            secret_key: None,
            p2p_port: 37000,
            identify_protocol: "/avail_kad/id/1.0.0".to_string(),
            identify_agent: "avail-light-client/rust-client".to_string(),
        }
    }
}
