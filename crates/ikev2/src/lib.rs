#![forbid(unsafe_code)]

mod auth;
mod child;
mod config;
mod crypto;
mod eap;
mod error;
mod forticlient;
mod message;
mod proposals;
mod rekey;
mod sa;
mod saml;
mod session;
mod setup;

use tokio_util::sync::CancellationToken;

pub use config::{Auth, Config};
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Why a tunnel ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `cancel` was triggered.
    Stopped,
    /// The gateway closed the tunnel or stopped answering.
    Down,
}

/// Runs the tunnel until it ends, then puts everything back.
///
/// # Errors
///
/// Anything that prevents the tunnel from coming up: the configuration,
/// the network, the gateway refusing us or the credentials.
pub async fn run(config: &Config, cancel: &CancellationToken) -> Result<Outcome> {
    // A SAML login replaces the configured user name and password.
    let with_saml;
    let mut device = None;
    let config = if config.saml_port.is_some() {
        let Some(credentials) = saml::log_in(config, cancel).await? else {
            return Ok(Outcome::Stopped);
        };
        device = Some(forticlient::Device {
            uid: credentials.uid,
        });
        with_saml = Config {
            username: credentials.username,
            password: Some(credentials.token),
            ..config.clone()
        };
        &with_saml
    } else {
        config
    };
    let mut session = session::Session::connect(config).await?;
    // The gateway ties the SAML login to the IKE session by device id.
    session.forticlient = device;
    let outcome = match setup::establish(&mut session, cancel).await {
        Ok(()) => match session.watch(cancel).await {
            Ok(session::Ended::Stopped) | Err(Error::Interrupted) => Ok(Outcome::Stopped),
            Ok(session::Ended::Down) => Ok(Outcome::Down),
            Err(Error::Down(reason)) => {
                tracing::warn!("The tunnel went down: {reason}.");
                Ok(Outcome::Down)
            }
            Err(error) => Err(error),
        },
        Err(Error::Interrupted) => {
            tracing::info!("Interrupted while establishing the tunnel.");
            Ok(Outcome::Stopped)
        }
        Err(error) => {
            if session::gateway_gone(&error) {
                session.down = Some(error.to_string());
            }
            Err(error)
        }
    };
    session.teardown().await;
    outcome
}
