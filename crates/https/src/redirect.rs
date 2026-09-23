//! RFC 9112 (the browser's request), RFC 3986 (percent-decoding).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::{Error, Result};

/// Requests that are not the redirect before giving up.
const MAX_BAD_REQUESTS: usize = 5;
/// How long a browser gets to send its request once connected.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Waits on `port` for the browser's redirect; `parse` reads what the
/// client needs from the request text (its own error is shown in the
/// browser). `None` when cancelled.
pub async fn wait_for<T>(
    port: u16,
    cancel: &CancellationToken,
    parse: impl Fn(&str) -> std::result::Result<T, String>,
) -> Result<Option<T>> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = TcpListener::bind(address)
        .await
        .map_err(|source| Error::Connect {
            what: format!("local server on {address}"),
            source,
        })?;
    tracing::info!("Listening for the browser login on port {port}");
    let mut bad_requests = 0;
    while bad_requests < MAX_BAD_REQUESTS {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = cancel.cancelled() => return Ok(None),
        };
        let (mut socket, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::error!("Failed to accept connection: {error}");
                bad_requests += 1;
                continue;
            }
        };
        tracing::debug!("incoming HTTP connection from {peer}");
        let handled = tokio::select! {
            handled = tokio::time::timeout(REQUEST_TIMEOUT, handle(&mut socket, &parse)) => handled,
            () = cancel.cancelled() => return Ok(None),
        };
        match handled {
            Ok(Ok(value)) => return Ok(Some(value)),
            Ok(Err(message)) => tracing::warn!("Failed to process request: {message}"),
            Err(_) => tracing::warn!("Failed to process request: no request received"),
        }
        bad_requests += 1;
    }
    Err(Error::Redirect("no valid redirect received".into()))
}

/// Reads one request and answers it.
async fn handle<T>(
    socket: &mut TcpStream,
    parse: &impl Fn(&str) -> std::result::Result<T, String>,
) -> std::result::Result<T, String> {
    let mut request = vec![0u8; 4096];
    let read = socket
        .read(&mut request)
        .await
        .map_err(|error| error.to_string())?;
    request.truncate(read);
    let request = String::from_utf8_lossy(&request);
    let result = parse(&request);
    let message = match &result {
        Ok(_) => {
            "Login received from the Fortinet gateway. VPN will be established...<br>\r\n\
             You may close this browser tab now.<br>\r\n\
             <script>\r\n\
             window.setTimeout(() => { window.close(); }, 5000);\r\n\
             document.write(\"<br>This window will close automatically in 5 seconds.\");\r\n\
             </script>\r\n"
        }
        Err(message) => message.as_str(),
    };
    let body = format!("<!DOCTYPE html>\r\n<html><body>\r\n{message}</body></html>\r\n");
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if let Err(error) = socket.write_all(reply.as_bytes()).await {
        tracing::warn!("Failed to write: {error}");
    }
    result
}

/// The query parameters of the request line of a `GET /?a=1&b=2` request:
/// each parameter's name and its percent-decoded value, in order.
#[must_use]
pub fn query_parameters(request: &str) -> Vec<(String, String)> {
    let Some(rest) = request.strip_prefix("GET /?") else {
        return Vec::new();
    };
    let query = rest.split([' ', '\r', '\n']).next().unwrap_or_default();
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (name.to_owned(), percent_decode(value)))
        .collect()
}

/// Decodes `%XX` escapes and `+`.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let escape = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok());
                if let Some(byte) = escape {
                    decoded.push(byte);
                    index += 3;
                } else {
                    decoded.push(b'%');
                    index += 1;
                }
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parameters_are_decoded() {
        let request = "GET /?id=abc-123&user=al%40ice+b%2Fc HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(
            query_parameters(request),
            vec![
                ("id".to_owned(), "abc-123".to_owned()),
                ("user".to_owned(), "al@ice b/c".to_owned())
            ]
        );
        assert!(query_parameters("GET /favicon.ico HTTP/1.1\r\n").is_empty());
        assert_eq!(percent_decode("a%zz%4"), "a%zz%4");
    }
}
