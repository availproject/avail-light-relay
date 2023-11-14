#![doc = include_str!("../README.md")]

use anyhow::{Context, Result};
use clap::Parser;
use libp2p::{
    futures::StreamExt,
    identify::{self, Info},
    identity::Keypair,
    multiaddr::Protocol,
    noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use multihash::{self, Hasher};
use std::net::Ipv4Addr;
use tracing::{debug, error, info, metadata::ParseLevelError, warn, Level};
use tracing_subscriber::{
    fmt::format::{self, DefaultFields, Format, Full, Json},
    FmtSubscriber,
};
use types::SecretKey;

mod server;
mod types;

#[derive(Debug, Parser)]
#[clap(name = "Avail Relay Server")]
struct CliOpts {
    #[clap(
        long,
        short = 'C',
        default_value = "config.yaml",
        help = "yaml configuration file"
    )]
    config: String,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    relay: relay::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}

fn parse_log_lvl(log_lvl: &str, default: Level) -> (Level, Option<ParseLevelError>) {
    log_lvl
        .to_uppercase()
        .parse::<Level>()
        .map(|lvl| (lvl, None))
        .unwrap_or_else(|err| (default, Some(err)))
}

fn json_subscriber(log_lvl: Level) -> FmtSubscriber<DefaultFields, Format<Json>> {
    FmtSubscriber::builder()
        .with_max_level(log_lvl)
        .event_format(format::json())
        .finish()
}

fn default_subscriber(log_lvl: Level) -> FmtSubscriber<DefaultFields, Format<Full>> {
    FmtSubscriber::builder()
        .with_max_level(log_lvl)
        .with_span_events(format::FmtSpan::CLOSE)
        .finish()
}

fn generate_id_keys(secret_key: Option<SecretKey>) -> Result<Keypair> {
    let id_keys = match secret_key {
        // if seed was provided, then generate secret key from that seed
        Some(SecretKey::Seed { seed }) => {
            let seed_digest = multihash::Sha3_256::digest(seed.as_bytes());
            Keypair::ed25519_from_bytes(seed_digest)
                .context("could not generate keypair from seed")?
        }
        // import provided secret key
        Some(SecretKey::Key { key }) => {
            let mut decoded_key = [0u8; 32];
            hex::decode_to_slice(key.into_bytes(), &mut decoded_key)
                .context("could not decode secret key from config")?;
            Keypair::ed25519_from_bytes(decoded_key).context("could not import secret key")?
        }
        // if neither seed nor secrete key were provided, generate keypair from random seed
        None => Keypair::generate_ed25519(),
    };

    Ok(id_keys)
}

fn create_swarm(
    id_keys: Keypair,
    protocol_version: String,
    agent_version: String,
) -> Result<Swarm<Behaviour>> {
    let local_peer_id = PeerId::from(id_keys.public());
    info!("Local peer id: {:?}.", local_peer_id,);

    Ok(SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().port_reuse(true).nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_behaviour(|key| Behaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), Default::default()),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new(protocol_version, key.public())
                    .with_agent_version(agent_version),
            ),
        })?
        .build())
}

async fn run() -> Result<()> {
    let opts = CliOpts::parse();
    let cfg_path = &opts.config;
    let cfg: RuntimeConfig = confy::load_path(cfg_path)
        .context(format!("Failed to load configuration from path {cfg_path}"))?;

    let (log_lvl, parse_err) = parse_log_lvl(&cfg.log_level, Level::INFO);
    // set json trace format
    if cfg.log_format_json {
        tracing::subscriber::set_global_default(json_subscriber(log_lvl))
            .expect("global json subscriber to be set");
    } else {
        tracing::subscriber::set_global_default(default_subscriber(log_lvl))
            .expect("global default subscriber to be set");
    }
    if let Some(err) = parse_err {
        warn!("Using default log level: {err}");
    }

    info!("Relay node starting ...");

    tokio::spawn(server::run((&cfg).into()));

    let mut swarm = create_swarm(
        generate_id_keys(cfg.secret_key)?,
        cfg.identify_protocol,
        cfg.identify_agent,
    )?;

    // listen on all interfaces on UDP
    swarm.listen_on(
        Multiaddr::empty()
            .with(Protocol::from(Ipv4Addr::UNSPECIFIED))
            .with(Protocol::Udp(cfg.p2p_port))
            .with(Protocol::QuicV1),
    )?;

    // listen on all interfaces on TCP
    swarm.listen_on(
        Multiaddr::empty()
            .with(Protocol::from(Ipv4Addr::UNSPECIFIED))
            .with(Protocol::Tcp(cfg.p2p_port + 1)),
    )?;

    tokio::spawn(async move {
        loop {
            match swarm.next().await.expect("Stream to be infinite.") {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Relay is listening on {address:?}");
                }

                SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => match event {
                    identify::Event::Received {
                        peer_id,
                        info: Info { listen_addrs, .. },
                    } => {
                        debug!("Identity Received from: {peer_id:?} on listen address: {listen_addrs:?}");
                    }

                    identify::Event::Sent { peer_id } => {
                        debug!("Identity Sent event to: {peer_id:?}");
                    }

                    _ => {}
                },

                SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => match event {
                    relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                        debug!("Relay accepted reservation request from: {src_peer_id:#?}");
                    }
                    relay::Event::ReservationReqDenied { src_peer_id } => {
                        debug!("Reservation request was denied for: {src_peer_id:#?}");
                    }
                    relay::Event::ReservationTimedOut { src_peer_id } => {
                        debug!("Reservation timed out for: {src_peer_id:#?}");
                    }
                    _ => {}
                },

                _ => {}
            }
        }
    }).await.context("Event loop failed to run")
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await.map_err(|err| {
        error!("{err}");
        err
    })
}
