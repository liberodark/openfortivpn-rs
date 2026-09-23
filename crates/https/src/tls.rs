//! RFC 9110 (CONNECT through an HTTPS proxy); TLS itself is rustls.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName, UnixTime,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{Error, Result, Settings};

/// Lowest TLS version accepted from the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MinTls {
    /// TLS 1.2, the oldest version rustls implements.
    #[default]
    Tls12,
    /// TLS 1.3 only.
    Tls13,
}

impl std::str::FromStr for MinTls {
    type Err = String;

    /// Accepts openfortivpn's `1.0`, `1.1`, `1.2` and `1.3`; the versions
    /// rustls does not implement are rounded up to 1.2, with a warning.
    fn from_str(version: &str) -> std::result::Result<Self, Self::Err> {
        match version {
            "1.0" | "1.1" => {
                tracing::warn!("TLS {version} is not supported, using TLS 1.2 as the minimum.");
                Ok(MinTls::Tls12)
            }
            "1.2" => Ok(MinTls::Tls12),
            "1.3" => Ok(MinTls::Tls13),
            other => Err(format!("unknown TLS version \"{other}\"")),
        }
    }
}

pub type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Opens TLS connections to the gateway, the same way every time.
pub struct Connector {
    tls: TlsConnector,
    gateway: String,
    port: u16,
    server_name: ServerName<'static>,
    bind_interface: Option<String>,
    proxy: Option<Proxy>,
}

/// An HTTPS proxy from the environment.
#[derive(Debug)]
struct Proxy {
    host: String,
    port: u16,
}

impl Proxy {
    /// Reads `https_proxy` (or `all_proxy`) from the environment.
    fn from_env(default_port: u16) -> Option<Self> {
        let value = ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
            .iter()
            .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))?;
        let proxy = Self::parse(&value, default_port);
        if let Some(proxy) = &proxy {
            tracing::debug!("using proxy {}:{}", proxy.host, proxy.port);
        } else {
            tracing::warn!("Ignoring the proxy setting \"{value}\": bad port.");
        }
        proxy
    }

    /// Parses `[scheme://]host[:port][/]`.
    fn parse(spec: &str, default_port: u16) -> Option<Self> {
        let spec = spec.trim_end_matches('/');
        let spec = spec.split_once("://").map_or(spec, |(_, rest)| rest);
        let (host, port) = match spec.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port.parse().ok()?),
            _ => (spec, default_port),
        };
        Some(Self {
            host: host.to_owned(),
            port,
        })
    }
}

impl Connector {
    /// Loads the roots, the trusted digests and the client certificate.
    pub fn new(config: &Settings) -> Result<Self> {
        let host_name = ServerName::try_from(config.gateway.clone())
            .map_err(|_| Error::Config(format!("Invalid gateway host \"{}\"", config.gateway)))?;
        let server_name = match &config.sni {
            Some(sni) => ServerName::try_from(sni.clone())
                .map_err(|_| Error::Config(format!("Invalid SNI \"{sni}\"")))?,
            None => host_name.clone(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = Arc::new(root_store(config)?);
        let verifier = Verifier {
            inner: WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
                .build()
                .map_err(|error| Error::Config(error.to_string()))?,
            host_name,
            trusted: config
                .trusted_certs
                .iter()
                .filter_map(|digest| hex::decode(digest).ok())
                .collect(),
        };
        let versions: &[&rustls::SupportedProtocolVersion] = match config.min_tls {
            MinTls::Tls12 => &[&rustls::version::TLS12, &rustls::version::TLS13],
            MinTls::Tls13 => &[&rustls::version::TLS13],
        };
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(Error::Tls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
        let tls = match (&config.user_cert, &config.user_key) {
            (Some(cert_path), Some(key_path)) => {
                let chain = ofv_pki::certificates(cert_path)?
                    .into_iter()
                    .map(|cert| CertificateDer::from(cert.der().to_vec()))
                    .collect();
                let key = private_key_der(&ofv_pki::private_key(
                    key_path,
                    config.pem_passphrase.as_ref(),
                )?);
                tracing::debug!("using client certificate {}", cert_path.display());
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(Error::Tls)?
            }
            _ => builder.with_no_client_auth(),
        };
        Ok(Self {
            tls: TlsConnector::from(Arc::new(tls)),
            gateway: config.gateway.clone(),
            port: config.port,
            server_name,
            bind_interface: config.bind_interface.clone(),
            proxy: Proxy::from_env(config.port),
        })
    }

    /// Opens a new connection and completes the TLS handshake.
    pub async fn connect(&self) -> Result<TlsStream> {
        let tcp = match &self.proxy {
            Some(proxy) => self.connect_through(proxy).await?,
            None => self.tcp_connect(&self.gateway, self.port).await?,
        };
        tracing::debug!("TLS handshake with SNI {:?}", self.server_name);
        let stream = self
            .tls
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|error| match error.get_ref() {
                Some(inner)
                    if inner
                        .downcast_ref::<rustls::Error>()
                        .is_some_and(is_cert_error) =>
                {
                    Error::Certificate
                }
                _ => Error::Io(error),
            })?;
        let (_, connection) = stream.get_ref();
        tracing::debug!(
            "TLS connection established ({:?}, {:?})",
            connection.protocol_version(),
            connection
                .negotiated_cipher_suite()
                .map(|suite| suite.suite())
        );
        Ok(stream)
    }

    async fn connect_through(&self, proxy: &Proxy) -> Result<TcpStream> {
        let mut tcp = self.tcp_connect(&proxy.host, proxy.port).await?;
        let target = format!("{}:{}", self.gateway, self.port);
        let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        tcp.write_all(request.as_bytes()).await?;
        // The proxy's reply, up to the end of its headers, one byte at a
        // time so that nothing of the TLS handshake is swallowed.
        let mut reply = Vec::new();
        loop {
            let byte = tcp
                .read_u8()
                .await
                .map_err(|_| Error::Proxy("connection closed before the CONNECT reply".into()))?;
            reply.push(byte);
            if reply.ends_with(b"\r\n\r\n") || reply.ends_with(b"\n\n") {
                break;
            }
            if reply.len() > 8192 {
                return Err(Error::Proxy("reply too long".into()));
            }
        }
        let reply = String::from_utf8_lossy(&reply);
        let status = reply.lines().next().unwrap_or_default();
        if status.split_whitespace().nth(1) != Some("200") {
            return Err(Error::Proxy(status.to_owned()));
        }
        Ok(tcp)
    }

    async fn tcp_connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let what = format!("{host}:{port}");
        let connect_error = |source| Error::Connect {
            what: what.clone(),
            source,
        };
        let mut addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(connect_error)?
            .collect();
        // The tunnel carries IPv4: prefer reaching the gateway over IPv4 too.
        addresses.sort_by_key(SocketAddr::is_ipv6);
        let mut last_error = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no address found for the host",
        );
        for address in addresses {
            tracing::debug!("connecting to {address}");
            match self.tcp_connect_to(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    tracing::debug!("could not connect to {address}: {error}");
                    last_error = error;
                }
            }
        }
        Err(connect_error(last_error))
    }

    async fn tcp_connect_to(&self, address: SocketAddr) -> std::io::Result<TcpStream> {
        let socket = match address.ip() {
            IpAddr::V4(_) => TcpSocket::new_v4()?,
            IpAddr::V6(_) => TcpSocket::new_v6()?,
        };
        if let Some(interface) = &self.bind_interface {
            bind_to_interface(&socket, interface, address.is_ipv4())?;
        }
        // Every PPP packet is one small TLS record: do not let Nagle hold
        // them back.
        socket.set_nodelay(true)?;
        socket.connect(address).await
    }
}

/// Sends the connection through `interface` (`SO_BINDTODEVICE`).
#[cfg(target_os = "linux")]
fn bind_to_interface(socket: &TcpSocket, interface: &str, _ipv4: bool) -> std::io::Result<()> {
    socket.bind_device(Some(interface.as_bytes()))
}

/// Sends the connection through `interface` by binding to its address.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn bind_to_interface(socket: &TcpSocket, interface: &str, ipv4: bool) -> std::io::Result<()> {
    let address = nix::ifaddrs::getifaddrs()?
        .filter(|entry| entry.interface_name == interface)
        .find_map(|entry| {
            let address = entry.address?;
            if ipv4 {
                address.as_sockaddr_in().map(|inet| IpAddr::V4(inet.ip()))
            } else {
                address.as_sockaddr_in6().map(|inet| IpAddr::V6(inet.ip()))
            }
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("interface {interface} has no suitable address"),
            )
        })?;
    socket.bind(SocketAddr::new(address, 0))
}

fn is_cert_error(error: &rustls::Error) -> bool {
    matches!(error, rustls::Error::InvalidCertificate(_))
}

/// The system roots plus the `--ca-file` bundle.
fn root_store(config: &Settings) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for error in &native.errors {
        tracing::debug!("loading the system certificates: {error}");
    }
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    tracing::debug!("loaded {added} system root certificates ({ignored} ignored)");
    if let Some(path) = &config.ca_file {
        for cert in ofv_pki::certificates(path)? {
            roots
                .add(CertificateDer::from(cert.der().to_vec()))
                .map_err(Error::Tls)?;
        }
        tracing::debug!("loaded the CA bundle {}", path.display());
    } else if added == 0 {
        tracing::warn!("No system root certificates found; use --ca-file or --trusted-cert.");
    }
    Ok(roots)
}

fn private_key_der(key: &ofv_pki::PrivateKey) -> PrivateKeyDer<'static> {
    let der = key.der().to_vec();
    match key.format() {
        ofv_pki::KeyFormat::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
        ofv_pki::KeyFormat::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
        ofv_pki::KeyFormat::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
    }
}

/// Checks the gateway certificate against the roots and the gateway host
/// (not the SNI), then against the trusted digests.
#[derive(Debug)]
struct Verifier {
    inner: Arc<WebPkiServerVerifier>,
    host_name: ServerName<'static>,
    trusted: Vec<Vec<u8>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            &self.host_name,
            ocsp_response,
            now,
        );
        let Err(error) = result else {
            tracing::debug!("gateway certificate validation succeeded");
            return result;
        };
        tracing::debug!("gateway certificate validation failed: {error}");
        let digest = Sha256::digest(end_entity.as_ref());
        if self.trusted.iter().any(|trusted| trusted[..] == digest[..]) {
            tracing::debug!("gateway certificate digest found in the trusted list");
            return Ok(ServerCertVerified::assertion());
        }
        report_untrusted(end_entity, &hex::encode(digest));
        Err(error)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Tells the user how to trust the certificate, and what it says about
/// itself.
fn report_untrusted(cert: &CertificateDer<'_>, digest: &str) {
    tracing::error!(
        "Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:"
    );
    tracing::error!("    --trusted-cert {digest}");
    tracing::error!("or add this line to your configuration file:");
    tracing::error!("    trusted-cert = {digest}");
    tracing::error!("Gateway certificate:");
    if let Ok((_, parsed)) = X509Certificate::from_der(cert.as_ref()) {
        tracing::error!("    subject: {}", parsed.subject());
        tracing::error!("    issuer: {}", parsed.issuer());
    }
    tracing::error!("    sha256 digest: {digest}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_specs() {
        let cases = [
            ("http://proxy.example:3128/", ("proxy.example", 3128)),
            ("proxy.example", ("proxy.example", 443)),
            ("http://10.0.0.1:8080", ("10.0.0.1", 8080)),
            ("socks5://proxy/", ("proxy", 443)),
        ];
        for (spec, (host, port)) in cases {
            let proxy = Proxy::parse(spec, 443).expect("proxy");
            assert_eq!((proxy.host.as_str(), proxy.port), (host, port));
        }
        assert!(Proxy::parse("proxy:x", 443).is_none());
    }
}
