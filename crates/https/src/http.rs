//! RFC 9112 (HTTP/1.1 messages, chunked bodies), RFC 3986 (percent-encoding).

use std::borrow::Cow;
use std::fmt::Write as _;

use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::tls::{Connector, TlsStream};
use crate::{Error, Result, Settings};

/// Responses larger than this are not something a gateway sends.
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// A parsed HTTP response.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// The status line's reason phrase.
    pub reason: String,
    /// Header names and values, in order.
    pub headers: Vec<(String, String)>,
    /// Body, de-chunked.
    pub body: Vec<u8>,
}

impl Response {
    /// The first header called `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers(name).next()
    }

    /// Every header called `name` (case-insensitive).
    pub fn headers<'r>(&'r self, name: &str) -> impl Iterator<Item = &'r str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(&name))
            .map(|(_, value)| value.as_str())
    }

    #[must_use]
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    #[must_use]
    pub fn contains(&self, needle: &[u8]) -> bool {
        self.body
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// Fails unless the status is 200.
    pub fn ok(self) -> Result<Self> {
        if self.status == 200 {
            Ok(self)
        } else {
            Err(Error::Status(self.status))
        }
    }
}

/// Percent-encodes everything but the unreserved characters.
#[must_use]
pub fn url_encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("writing to a String");
        }
    }
    encoded
}

/// The HTTP side of the portal connection.
pub struct Client<'a> {
    connector: &'a Connector,
    stream: Option<TlsStream>,
    host: String,
    user_agent: String,
    cookie: Option<SecretString>,
}

impl<'a> Client<'a> {
    /// A client for the gateway of `config`; the connection is opened on
    /// the first request.
    #[must_use]
    pub fn new(connector: &'a Connector, config: &Settings) -> Self {
        Self {
            connector,
            stream: None,
            host: format!("{}:{}", config.gateway, config.port),
            user_agent: config.user_agent.clone(),
            cookie: None,
        }
    }

    /// Opens a fresh connection, dropping the current one.
    pub async fn reconnect(&mut self) -> Result<()> {
        self.stream = None;
        self.stream = Some(self.connector.connect().await?);
        Ok(())
    }

    /// The session cookie sent with every request.
    #[must_use]
    pub fn cookie(&self) -> Option<&SecretString> {
        self.cookie.as_ref()
    }

    /// Sets the session cookie sent with every request.
    pub fn set_cookie(&mut self, cookie: SecretString) {
        self.cookie = Some(cookie);
    }

    /// Hands over the connection, for the tunnel to use it raw.
    async fn take_stream(&mut self) -> Result<TlsStream> {
        if self.stream.is_none() {
            self.reconnect().await?;
        }
        Ok(self.stream.take().expect("just connected"))
    }

    /// Sends `GET path` with `host` as the Host header and hands over the
    /// connection without reading the response: the gateway then speaks
    /// something else than HTTP on it.
    pub async fn take_over(&mut self, path: &str, host: &str) -> Result<TlsStream> {
        let mut stream = self.take_stream().await?;
        let cookie = self
            .cookie
            .as_ref()
            .map_or("", |cookie| cookie.expose_secret());
        let request = Zeroizing::new(format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n\r\n"
        ));
        tracing::debug!("GET {path}");
        stream.write_all(request.as_bytes()).await?;
        Ok(stream)
    }

    pub async fn get(&mut self, path: &str) -> Result<Response> {
        self.request("GET", path, "application/x-www-form-urlencoded", "")
            .await
    }

    /// `POST path` with a form-encoded body.
    pub async fn post(&mut self, path: &str, form: &str) -> Result<Response> {
        self.request("POST", path, "application/x-www-form-urlencoded", form)
            .await
    }

    /// `POST path` with a JSON body.
    pub async fn post_json(&mut self, path: &str, json: &str) -> Result<Response> {
        self.request("POST", path, "application/json", json).await
    }

    /// One request; a connection the gateway closed is reopened once.
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &str,
    ) -> Result<Response> {
        let cookie = self
            .cookie
            .as_ref()
            .map_or("", |cookie| cookie.expose_secret());
        let request = Zeroizing::new(format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: */*\r\n\
             Accept-Encoding: identity\r\n\
             Pragma: no-cache\r\n\
             Cache-Control: no-store, no-cache, must-revalidate\r\n\
             If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n\
             Content-Type: {content_type}\r\n\
             Cookie: {cookie}\r\n\
             Content-Length: {}\r\n\
             \r\n{body}",
            self.host,
            self.user_agent,
            body.len()
        ));
        tracing::debug!("{method} {path}");
        let mut reconnected = self.stream.is_none();
        loop {
            if self.stream.is_none() {
                self.reconnect().await?;
            }
            let stream = self.stream.as_mut().expect("connected");
            match exchange(stream, &request).await {
                Ok(response) => {
                    tracing::debug!("{method} {path}: {}", response.status);
                    tracing::trace!(
                        "response headers: {:?}\nresponse body:\n{}",
                        response.headers,
                        response.text()
                    );
                    return Ok(response);
                }
                Err(Error::Io(error)) if !reconnected => {
                    tracing::debug!("{method} {path}: {error}; reconnecting");
                    self.stream = None;
                    reconnected = true;
                }
                Err(error) => {
                    self.stream = None;
                    return Err(error);
                }
            }
        }
    }
}

/// Writes one request and reads its response.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &str,
) -> Result<Response> {
    stream.write_all(request.as_bytes()).await?;
    let mut reader = Reader {
        stream,
        buffer: Vec::with_capacity(4096),
    };
    let head = reader.read_until(b"\r\n\r\n").await?;
    let head = String::from_utf8_lossy(&head).into_owned();
    let (status_line, header_lines) = head.split_once("\r\n").unwrap_or((&head, ""));
    let mut words = status_line
        .strip_prefix("HTTP/1.")
        .unwrap_or_default()
        .splitn(3, ' ');
    let status = words
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| Error::Http(format!("bad status line \"{status_line}\"")))?;
    let reason = words.next().unwrap_or_default().trim().to_owned();
    let headers: Vec<(String, String)> = header_lines
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let response = Response {
        status,
        reason,
        headers,
        body: Vec::new(),
    };

    let chunked = response
        .header("Transfer-Encoding")
        .is_some_and(|encoding| encoding.eq_ignore_ascii_case("chunked"));
    let content_length: Option<usize> = response
        .header("Content-Length")
        .map(|length| {
            length
                .parse()
                .map_err(|_| Error::Http(format!("bad Content-Length \"{length}\"")))
        })
        .transpose()?;
    let close = response
        .header("Connection")
        .is_some_and(|value| value.eq_ignore_ascii_case("close"));
    let body = if chunked {
        reader.read_chunked().await?
    } else if let Some(length) = content_length {
        reader.read_exact(length).await?
    } else if close {
        reader.read_to_end().await?
    } else {
        Vec::new()
    };
    Ok(Response { body, ..response })
}

/// Buffered reads of delimited and sized pieces.
struct Reader<'a, S> {
    stream: &'a mut S,
    buffer: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Reader<'_, S> {
    /// Fills the buffer with at least one more byte.
    async fn fill(&mut self) -> Result<()> {
        if self.buffer.len() >= MAX_RESPONSE {
            return Err(Error::Http("response too long".into()));
        }
        let mut chunk = [0u8; 8192];
        let read = self.stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the gateway closed the connection",
            )));
        }
        self.buffer.extend_from_slice(&chunk[..read]);
        Ok(())
    }

    /// Everything up to `delimiter`, which is consumed but not returned.
    async fn read_until(&mut self, delimiter: &[u8]) -> Result<Vec<u8>> {
        loop {
            if let Some(index) = self
                .buffer
                .windows(delimiter.len())
                .position(|window| window == delimiter)
            {
                let mut rest = self.buffer.split_off(index + delimiter.len());
                std::mem::swap(&mut rest, &mut self.buffer);
                rest.truncate(index);
                return Ok(rest);
            }
            self.fill().await?;
        }
    }

    async fn read_exact(&mut self, length: usize) -> Result<Vec<u8>> {
        if length > MAX_RESPONSE {
            return Err(Error::Http("response too long".into()));
        }
        while self.buffer.len() < length {
            self.fill().await?;
        }
        let rest = self.buffer.split_off(length);
        Ok(std::mem::replace(&mut self.buffer, rest))
    }

    async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        loop {
            match self.fill().await {
                Ok(()) => {}
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(std::mem::take(&mut self.buffer));
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn read_chunked(&mut self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let size_line = self.read_until(b"\r\n").await?;
            let size_line = String::from_utf8_lossy(&size_line);
            let size = size_line
                .split(';')
                .next()
                .map(str::trim)
                .and_then(|hex| usize::from_str_radix(hex, 16).ok())
                .ok_or_else(|| Error::Http(format!("bad chunk size \"{size_line}\"")))?;
            if size == 0 {
                // Trailers, up to the empty line.
                while !self.read_until(b"\r\n").await?.is_empty() {}
                return Ok(body);
            }
            if size > MAX_RESPONSE || body.len() + size > MAX_RESPONSE {
                return Err(Error::Http("response too long".into()));
            }
            body.extend(self.read_exact(size).await?);
            self.read_until(b"\r\n").await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_urls() {
        assert_eq!(url_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(url_encode("p@ss w/é"), "p%40ss%20w%2F%C3%A9");
    }

    async fn parse(response: &[u8]) -> Result<Response> {
        let mut stream = tokio::io::join(response, tokio::io::sink());
        exchange(&mut stream, "GET / HTTP/1.1\r\n\r\n").await
    }

    #[tokio::test]
    async fn reads_sized_and_chunked_bodies() {
        let response = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        let response = parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              3;ext\r\nhel\r\n2\r\nlo\r\n0\r\nTrailer: x\r\n\r\n",
        )
        .await
        .expect("response");
        assert_eq!(response.body, b"hello");
        let response =
            parse(b"HTTP/1.1 401 Authorization Required\r\nConnection: close\r\n\r\nform")
                .await
                .expect("response");
        assert_eq!(response.status, 401);
        assert_eq!(response.body, b"form");
        let response = parse(b"HTTP/1.1 403 Permission denied\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("response");
        assert_eq!(
            (response.status, response.reason.as_str()),
            (403, "Permission denied")
        );
        assert!(matches!(
            parse(b"garbage\r\n\r\n").await,
            Err(Error::Http(_))
        ));
        assert!(matches!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel").await,
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn finds_headers_case_insensitively() {
        let response = Response {
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Set-Cookie".into(), "a=1".into()),
                ("set-cookie".into(), "b=2".into()),
            ],
            body: b"hello".to_vec(),
        };
        assert_eq!(response.header("SET-COOKIE"), Some("a=1"));
        assert_eq!(response.headers("Set-Cookie").count(), 2);
        assert_eq!(response.text(), "hello");
        assert!(response.contains(b"ell") && !response.contains(b"x"));
        assert!(matches!(
            Response {
                status: 403,
                reason: String::new(),
                headers: Vec::new(),
                body: Vec::new()
            }
            .ok(),
            Err(Error::Status(403))
        ));
    }
}
