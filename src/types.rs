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
    /// Secret key for libp2p keypair. Can be either set to `seed` or to `key`.
    /// If set to seed, keypair will be generated from that seed.
    /// If set to key, a valid ed25519 private key must be provided, else the client will fail
    /// If `secret_key` is not set, random seed will be used.
    pub secret_key: Option<SecretKey>,
    /// Sets Libp2p service port. (default: 37000)
    pub libp2p_port: u16,
    /// Sets libp2p application-specific version of the protocol family used by the peer. (default: "/avail_kad/id/1.0.0")
    pub libp2p_identify_protocol: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        RuntimeConfig {
            log_level: "INFO".to_owned(),
            log_format_json: false,
            secret_key: None,
            libp2p_port: 37000,
            libp2p_identify_protocol: "/avail_kad/id/1.0.0".to_owned(),
        }
    }
}
