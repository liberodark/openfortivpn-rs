use ofv_https::redirect;
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::{Error, Result};

/// Waits for the browser to bring the SAML session id back.
pub async fn wait_for_session(
    config: &Config,
    port: u16,
    cancel: &CancellationToken,
) -> Result<Option<SecretString>> {
    let realm = if config.realm.is_empty() {
        String::new()
    } else {
        format!("&realm={}", ofv_https::http::url_encode(&config.realm))
    };
    tracing::info!(
        "Authenticate at 'https://{}:{}/remote/saml/start?redirect=1{realm}'",
        config.https.gateway,
        config.https.port
    );
    match redirect::wait_for(port, cancel, session_id).await {
        Ok(id) => Ok(id.map(SecretString::from)),
        Err(ofv_https::Error::Redirect(what)) => Err(Error::Saml(what)),
        Err(error) => Err(error.into()),
    }
}

/// The `id` of a `GET /?id=<id>` request line.
fn session_id(request: &str) -> std::result::Result<String, String> {
    let rest = request.strip_prefix("GET /?id=").ok_or_else(|| {
        "Invalid redirect response from Fortinet server. VPN could not be established.".to_owned()
    })?;
    let id = rest
        .split([' ', '&', '\r', '\n'])
        .next()
        .unwrap_or_default();
    if id.is_empty()
        || id.len() > 1024
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(
            "Invalid SAML session id received from Fortinet server. VPN could not be established."
                .to_owned(),
        );
    }
    Ok(id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_session_ids() {
        assert_eq!(
            session_id("GET /?id=abc-123 HTTP/1.1\r\nHost: x\r\n\r\n").as_deref(),
            Ok("abc-123")
        );
        assert_eq!(
            session_id("GET /?id=abc&x=1 HTTP/1.1\r\n").as_deref(),
            Ok("abc")
        );
        assert!(session_id("GET /favicon.ico HTTP/1.1\r\n").is_err());
        assert!(session_id("GET /?id= HTTP/1.1\r\n").is_err());
        assert!(session_id("GET /?id=a/b HTTP/1.1\r\n").is_err());
    }
}
