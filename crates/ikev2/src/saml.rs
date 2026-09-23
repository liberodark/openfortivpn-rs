//! No specification: the SAML login of FortiClient's IPsec VPN, as FortiClient
//! 7.4.8's iked does it (FortiOS `ike-saml-server`).

use ofv_https::http::{Client, Response};
use ofv_https::{Connector, MinTls, Settings, redirect};
use rand_core::{OsRng, RngCore};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::{Error, Result};

/// What FortiClient's IKE daemon sends as `User-Agent`.
const USER_AGENT: &str = "FortiSSLVPN (Linux; SV1 [SV{v=02.01; f=05;}])";
/// Where the gateway hands out the SAML login URL.
const LOGIN_PATH: &str = "/saml_login?";

/// The credentials a SAML login produced, and the device identifier the
/// login was requested with.
pub struct Credentials {
    pub username: String,
    pub token: SecretString,
    pub uid: String,
}

/// Runs the SAML login: `None` when cancelled while waiting for the
/// browser.
pub async fn log_in(config: &Config, cancel: &CancellationToken) -> Result<Option<Credentials>> {
    let port = config.saml_port.expect("a SAML login");
    let settings = Settings {
        gateway: config.gateway.clone(),
        port: config.saml_gateway_port,
        sni: None,
        bind_interface: None,
        trusted_certs: config.trusted_certs.clone(),
        min_tls: MinTls::default(),
        ca_file: config.ca_file.clone(),
        user_cert: None,
        user_key: None,
        pem_passphrase: None,
        user_agent: USER_AGENT.to_owned(),
    };
    let connector = Connector::new(&settings)?;
    let mut client = Client::new(&connector, &settings);
    // A device identifier like FortiClient's, which the gateway sees again
    // in IKE_AUTH to tie the login to the tunnel.
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let uid = hex::encode_upper(random);
    let request =
        format!("{{\"type\": \"rawData\", \"bytes\": \"UID={uid}&REDIRECT_PORT={port}\"}}");
    tracing::info!(
        "Requesting the SAML login from https://{}:{}{LOGIN_PATH}",
        settings.gateway,
        settings.port
    );
    let response = client.post_json(LOGIN_PATH, &request).await?;
    tracing::debug!(
        "SAML login response: {} {}, {} bytes",
        response.status,
        response.reason,
        response.body.len()
    );
    let url = login_url(&response).ok_or_else(|| {
        Error::Saml(format!(
            "the gateway gave no SAML login URL ({} {}): {}",
            response.status,
            response.reason,
            response.text().chars().take(200).collect::<String>()
        ))
    })?;
    tracing::info!("Authenticate at '{url}'");
    let received = redirect::wait_for(port, cancel, |request| credentials(request, &uid)).await?;
    if let Some(credentials) = &received {
        tracing::info!("SAML login done for {}.", credentials.username);
    }
    Ok(received)
}

/// The login URL in the gateway's response: a redirect, or the first
/// `https://` URL of the body (JSON, HTML or plain).
fn login_url(response: &Response) -> Option<String> {
    if (300..400).contains(&response.status)
        && let Some(location) = response.header("Location")
    {
        return Some(location.to_owned());
    }
    // JSON escapes its slashes.
    let text = response.text().replace("\\/", "/");
    let start = text.find("https://")?;
    let url = text[start..]
        .split(['"', '\'', ' ', '<', '\r', '\n', '\\'])
        .next()?;
    Some(url.to_owned())
}

/// The `tokenid` and `username` the gateway sends the browser back with.
fn credentials(request: &str, uid: &str) -> std::result::Result<Credentials, String> {
    let parameters = redirect::query_parameters(request);
    let value = |name: &str| {
        parameters
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .filter(|value| !value.is_empty())
    };
    if let (Some(token), Some(username)) = (value("tokenid"), value("username")) {
        Ok(Credentials {
            username,
            token: SecretString::from(token),
            uid: uid.to_owned(),
        })
    } else {
        tracing::debug!(
            "unexpected browser request: {}",
            request.lines().next().unwrap_or_default()
        );
        Err(
            "Invalid redirect response from the Fortinet gateway (no token or user name). \
             VPN could not be established."
                .to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn finds_the_login_url() {
        let response = |status, reason: &str, body: &str| Response {
            status,
            reason: reason.to_owned(),
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        };
        assert_eq!(
            login_url(&response(
                200,
                "OK",
                r#"{"url":"https:\/\/idp.example\/sso?x=1"}"#
            )),
            Some("https://idp.example/sso?x=1".to_owned())
        );
        assert_eq!(
            login_url(&response(
                200,
                "OK",
                "https://gw/remote/saml/start?ike=1\r\n"
            )),
            Some("https://gw/remote/saml/start?ike=1".to_owned())
        );
        assert_eq!(login_url(&response(403, "Forbidden", "nope")), None);
    }

    #[test]
    fn reads_the_credentials() {
        let received = credentials(
            "GET /?tokenid=abc%2F123&username=alice%40example.com HTTP/1.1\r\nHost: x\r\n\r\n",
            "UID",
        )
        .expect("credentials");
        assert_eq!(received.username, "alice@example.com");
        assert_eq!(received.token.expose_secret(), "abc/123");
        assert_eq!(received.uid, "UID");
        assert!(credentials("GET /?tokenid=abc HTTP/1.1\r\n", "UID").is_err());
        assert!(credentials("GET /favicon.ico HTTP/1.1\r\n", "UID").is_err());
    }
}
