//! No specification: the FortiGate SSL VPN portal as openfortivpn drives it.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use ofv_https::http::{Client, Response, url_encode};
use ofv_https::{Connector, TlsStream};

use crate::config::{Config, Prompt};
use crate::{Error, Result};

const COOKIE_NAME: &str = "SVPNCOOKIE=";
const LOGIN_CHECK: &str = "/remote/logincheck";

/// Whether `cookie` is a session cookie as the gateway sets it.
#[must_use]
pub fn is_cookie(cookie: &SecretString) -> bool {
    cookie
        .expose_secret()
        .strip_prefix(COOKIE_NAME)
        .is_some_and(|value| !value.is_empty())
}

/// The cookie as the user gives it: with or without the `SVPNCOOKIE=`
/// prefix, possibly with the attributes of the `Set-Cookie` line.
#[must_use]
pub fn normalize_cookie(given: &str) -> SecretString {
    let value = given.trim();
    let value = value.strip_prefix(COOKIE_NAME).unwrap_or(value);
    let value = value.split([';', '\r', '\n']).next().unwrap_or_default();
    SecretString::from(format!("{COOKIE_NAME}{value}"))
}

/// What the gateway tells us about the tunnel before it starts.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VpnConfig {
    /// The address assigned to us (also negotiated over IPCP).
    pub address: Option<Ipv4Addr>,
    /// Nameservers, in order.
    pub dns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,
    /// Split-tunnel networks, as (address, prefix length); empty for a
    /// full tunnel.
    pub routes: Vec<(Ipv4Addr, u8)>,
}

/// The portal's way of refusing a request: a reason phrase, or a marker
/// in the page.
fn allowed(response: Response) -> Result<Response> {
    if response.reason.contains("permission_denied denied")
        || response.reason.contains("Permission denied")
        || response.contains(b"<!--sslvpnerrmsgkey=sslvpn_login_permission_denied-->")
    {
        return Err(Error::PermissionDenied);
    }
    Ok(response)
}

/// A session with the portal.
pub struct Portal<'a> {
    client: Client<'a>,
    config: &'a Config,
}

impl<'a> Portal<'a> {
    #[must_use]
    pub fn new(connector: &'a Connector, config: &'a Config) -> Self {
        Self {
            client: Client::new(connector, &config.https),
            config,
        }
    }

    /// `GET path`, with the portal's way of refusing a request.
    async fn get(&mut self, path: &str) -> Result<Response> {
        allowed(self.client.get(path).await?)
    }

    /// `POST path` with a form, with the portal's way of refusing it.
    async fn post(&mut self, path: &str, form: &str) -> Result<Response> {
        allowed(self.client.post(path, form).await?)
    }

    /// Obtains the session cookie: from the configuration, the SAML
    /// session or the login form, with the second factor when asked.
    pub async fn log_in(
        &mut self,
        prompt: &impl Prompt,
        saml_session: Option<&SecretString>,
    ) -> Result<()> {
        if let Some(cookie) = &self.config.cookie {
            self.client.set_cookie(cookie.clone());
            return Ok(());
        }
        let config = self.config;
        let username = url_encode(&config.username);
        let realm = url_encode(&config.realm);
        let response = if let Some(session) = saml_session {
            let path = format!(
                "/remote/saml/auth_id?id={}",
                url_encode(session.expose_secret())
            );
            self.get(&path).await?
        } else if config.username.is_empty() && config.password().is_none() {
            self.get("/remote/login").await?
        } else if let Some(password) = config.password() {
            let form = Zeroizing::new(format!(
                "username={username}&credential={}&realm={realm}&ajax=1",
                url_encode(password.expose_secret())
            ));
            self.post(LOGIN_CHECK, &form).await?
        } else {
            let form = format!(
                "username={username}&realm={realm}&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1"
            );
            self.post(LOGIN_CHECK, &form).await?
        };

        let body = response.text().into_owned();
        match value_of(&body, "ret=").map(str::parse::<u32>) {
            Some(Ok(0)) => {
                tracing::error!("Authentication failed");
                return Err(Error::Authentication);
            }
            Some(Ok(1)) => tracing::debug!("authentication succeeded"),
            Some(Ok(6)) => {
                tracing::error!("Gateway replied to authentication with an unsupported challenge");
                return Err(Error::Authentication);
            }
            Some(result) => tracing::warn!("Unknown authentication result: {result:?}"),
            None => {}
        }

        // A one-time password is probably needed.
        let response = if response.status == 401 {
            self.delay_otp().await;
            self.answer_otp_form(&body, prompt).await?
        } else {
            response
        };
        let response = response.ok()?;
        let body = response.text().into_owned();

        let response = if let Some(cookie) = cookie_of(&response) {
            self.client.set_cookie(cookie);
            response
        } else {
            // No cookie but a tokeninfo: the gateway expects a second
            // factor. Neither means the credentials were rejected.
            let Some(token) = value_of(&body, "tokeninfo=") else {
                return Err(Error::Authentication);
            };
            let response = self
                .second_factor(&body, token, &username, &realm, prompt)
                .await?
                .ok()?;
            let cookie = cookie_of(&response).ok_or(Error::Authentication)?;
            self.client.set_cookie(cookie);
            response
        };

        // With host checking enabled, the gateway wants a report.
        if let Some(action) = action_url(&response.text()) {
            let form = format!(
                "hostcheck={}&check_virtual_desktop={}",
                url_encode(self.config.hostcheck.as_deref().unwrap_or_default()),
                url_encode(
                    self.config
                        .check_virtual_desktop
                        .as_deref()
                        .unwrap_or_default()
                )
            );
            self.post(&action, &form).await?;
        }
        Ok(())
    }

    /// The session cookie, once logged in.
    #[must_use]
    pub fn cookie(&self) -> Option<&SecretString> {
        self.client.cookie()
    }

    async fn delay_otp(&self) {
        let delay = self.config.otp_delay;
        if delay > 0 {
            tracing::info!("Delaying OTP by {delay} seconds...");
            tokio::time::sleep(Duration::from_secs(u64::from(delay))).await;
        }
    }

    /// The one-time password: the configured one, or asked for.
    async fn otp(&self, prompt: &impl Prompt, message: &str, what: &str) -> Result<SecretString> {
        if let Some(otp) = &self.config.otp {
            return Ok(otp.clone());
        }
        let config = self.config;
        let key_info = format!(
            "{}_{}_{}_{what}",
            config.username, config.realm, config.https.gateway
        );
        prompt.secret(&key_info, message).await.map_err(Error::Otp)
    }

    /// Fills in the OTP form the gateway answered with.
    async fn answer_otp_form(&mut self, page: &str, prompt: &impl Prompt) -> Result<Response> {
        let form = OtpForm::parse(page, self.config.otp_prompt.as_deref())
            .ok_or_else(|| Error::Otp("could not parse the OTP form".into()))?;
        let otp = self.otp(prompt, &form.prompt, "otp").await?;
        let mut fields = form.hidden;
        let mut secret = format!(
            "{}={}",
            url_encode(&form.password),
            url_encode(otp.expose_secret())
        );
        if !self.config.realm.is_empty() {
            write!(secret, "&realm={}", url_encode(&self.config.realm))
                .expect("writing to a String");
        }
        fields.push(secret);
        let body = Zeroizing::new(fields.join("&"));
        self.post(&form.action, &body).await
    }

    /// Answers the two-factor challenge with a FortiToken push or a code.
    async fn second_factor(
        &mut self,
        body: &str,
        token: &str,
        username: &str,
        realm: &str,
        prompt: &impl Prompt,
    ) -> Result<Response> {
        let field = |key: &str| value_of(body, key).unwrap_or_default().to_owned();
        let magic = field("magic=");
        let token_params =
            if self.config.otp.is_none() && token.starts_with("ftm_push") && self.config.ftm_push {
                tracing::info!("Waiting for the FortiToken Mobile push to be approved...");
                Zeroizing::new("ftmpush=1".to_owned())
            } else {
                let code = self
                    .otp(prompt, "Two-factor authentication token:", "2fa")
                    .await?;
                Zeroizing::new(format!(
                    "code={}&code2=&magic={magic}",
                    url_encode(code.expose_secret())
                ))
            };
        let form = Zeroizing::new(format!(
            "username={username}&realm={realm}&reqid={}&polid={}&grp={}&portal={}&peer={}&{}",
            field("reqid="),
            field("polid="),
            field("grp="),
            field("portal="),
            field("peer="),
            token_params.as_str()
        ));
        self.delay_otp().await;
        self.post(LOGIN_CHECK, &form).await
    }

    /// Asks the gateway to allocate the VPN, then reconnects as the
    /// gateway expects.
    pub async fn allocate(&mut self) -> Result<()> {
        self.get("/remote/index").await?;
        self.get("/remote/fortisslvpn").await?;
        Ok(self.client.reconnect().await?)
    }

    pub async fn fetch_config(&mut self) -> Result<VpnConfig> {
        let response = self.get("/remote/fortisslvpn_xml").await?.ok()?;
        parse_vpn_config(&response.text())
    }

    /// Switches the connection to tunnel mode and hands it over.
    pub async fn start_tunnel(&mut self) -> Result<TlsStream> {
        Ok(self
            .client
            .take_over("/remote/sslvpn-tunnel", "sslvpn")
            .await?)
    }

    /// Ends the session on a fresh connection.
    pub async fn log_out(&mut self) {
        match self.client.reconnect().await {
            Ok(()) => match self.get("/remote/logout").await {
                Ok(_) => tracing::info!("Logged out."),
                Err(error) => tracing::info!("Could not log out ({error})."),
            },
            Err(error) => tracing::info!("Could not log out ({error})."),
        }
    }
}

/// The value of `key` in a `key1=value1&key2=value2` or comma-separated
/// body; `key` includes the `=`.
fn value_of<'b>(body: &'b str, key: &str) -> Option<&'b str> {
    body.split(['&', ',', '\r', '\n'])
        .find_map(|pair| pair.strip_prefix(key))
}

/// The session cookie of a response, if it sets one.
fn cookie_of(response: &Response) -> Option<SecretString> {
    cookie_in(response.headers("Set-Cookie"))
}

/// The session cookie among `Set-Cookie` header values.
fn cookie_in<'a>(lines: impl Iterator<Item = &'a str>) -> Option<SecretString> {
    lines.into_iter().find_map(|line| {
        let start = line.find(COOKIE_NAME)?;
        let cookie = &line[start..];
        let cookie = cookie.split([';', '\r', '\n']).next()?;
        if cookie.len() == COOKIE_NAME.len() {
            tracing::debug!("empty cookie");
            return None;
        }
        Some(SecretString::from(cookie))
    })
}

/// The `action=` URL of a host check page.
fn action_url(page: &str) -> Option<String> {
    let mut tokens = page.split([' ', '"', '\r', '\n']);
    tokens.find(|token| token.starts_with("action="))?;
    tokens.find(|token| !token.is_empty()).map(str::to_owned)
}

/// The OTP form of a `401` page.
#[derive(Debug, PartialEq, Eq)]
struct OtpForm {
    action: String,
    prompt: String,
    /// Hidden fields, already encoded as `name=value`.
    hidden: Vec<String>,
    /// Name of the password field.
    password: String,
}

/// Finds `<TAG` case-insensitively and returns the text up to `>`.
fn tags<'p>(page: &'p str, name: &str) -> impl Iterator<Item = &'p str> {
    let lower = page.to_ascii_lowercase();
    let pattern = format!("<{}", name.to_ascii_lowercase());
    let mut from = 0;
    std::iter::from_fn(move || {
        let start = lower[from..].find(&pattern)? + from + pattern.len();
        let end = lower[start..]
            .find('>')
            .map_or(lower.len(), |end| start + end);
        from = end;
        Some(&page[start..end])
    })
}

/// The value of attribute `name` in a tag, in double or single quotes.
fn attribute<'t>(tag: &'t str, name: &str) -> Option<&'t str> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(index) = lower[from..].find(&format!("{name}=")) {
        let start = from + index;
        let preceded_by_space = start == 0 || lower.as_bytes()[start - 1].is_ascii_whitespace();
        let value_start = start + name.len() + 1;
        from = value_start;
        if !preceded_by_space {
            continue;
        }
        let quote = tag.as_bytes().get(value_start).copied()?;
        if quote != b'"' && quote != b'\'' {
            continue;
        }
        let rest = &tag[value_start + 1..];
        return rest.split(char::from(quote)).next();
    }
    None
}

impl OtpForm {
    fn parse(page: &str, otp_prompt: Option<&str>) -> Option<Self> {
        let form_start = page.to_ascii_lowercase().find("<form")?;
        let page = &page[form_start..];
        let action = attribute(tags(page, "form").next()?, "action")?.to_owned();
        let prompt = page
            .find(otp_prompt.unwrap_or("Please"))
            .and_then(|start| {
                let text = &page[start..];
                let end = text.find('<')?;
                Some(text[..end].trim().to_owned())
            })
            .unwrap_or_else(|| "Please enter one-time password:".to_owned());
        let mut hidden = Vec::new();
        let mut password = None;
        for input in tags(page, "input") {
            let kind = attribute(input, "type")?.to_ascii_lowercase();
            let Some(name) = attribute(input, "name") else {
                continue;
            };
            match kind.as_str() {
                "hidden" => {
                    let value = attribute(input, "value")?;
                    hidden.push(format!("{}={}", url_encode(name), url_encode(value)));
                }
                "password" => password = Some(name.to_owned()),
                _ => {}
            }
        }
        Some(Self {
            action,
            prompt,
            hidden,
            password: password?,
        })
    }
}

/// Reads the `/remote/fortisslvpn_xml` document.
fn parse_vpn_config(xml: &str) -> Result<VpnConfig> {
    let mut config = VpnConfig::default();
    let parse_ip = |value: &str| {
        value
            .parse::<Ipv4Addr>()
            .map_err(|_| Error::VpnConfig(format!("bad address \"{value}\"")))
    };
    if let Some(tag) = tags(xml, "assigned-addr").next()
        && let Some(address) = attribute(tag, "ipv4")
    {
        config.address = Some(parse_ip(address)?);
    }
    if config.address.is_none() {
        tracing::warn!("No gateway address, using interface for routing");
    }
    for tag in tags(xml, "dns") {
        // Several suffixes come separated by semicolons.
        if let Some(domain) = attribute(tag, "domain").filter(|_| config.domains.is_empty()) {
            tracing::debug!("found DNS suffix {domain} in the XML configuration");
            config.domains = domain
                .split(';')
                .map(str::trim)
                .filter(|suffix| !suffix.is_empty())
                .map(str::to_owned)
                .collect();
        }
        if let Some(server) = attribute(tag, "ip") {
            tracing::debug!("found DNS server {server} in the XML configuration");
            config.dns.push(parse_ip(server)?);
        }
    }
    if let Some(start) = xml.find("<split-tunnel-info") {
        let section = &xml[start..];
        let section = section
            .find("</split-tunnel-info")
            .map_or(section, |end| &section[..end]);
        for tag in tags(section, "addr") {
            let (Some(address), Some(mask)) = (attribute(tag, "ip"), attribute(tag, "mask")) else {
                tracing::warn!("Route without address or mask in the XML configuration");
                continue;
            };
            let mask = u32::from(parse_ip(mask)?);
            if mask.count_ones() != mask.leading_ones() {
                return Err(Error::VpnConfig(format!(
                    "bad netmask {}",
                    Ipv4Addr::from(mask)
                )));
            }
            let prefix = u8::try_from(mask.leading_ones()).expect("at most 32");
            config.routes.push((parse_ip(address)?, prefix));
        }
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_values_and_cookies() {
        assert_eq!(value_of("ret=1,redir=/remote/index", "ret="), Some("1"));
        assert_eq!(
            value_of("ret=0&tokeninfo=ftm_push,reqid=12\r\n", "reqid="),
            Some("12")
        );
        assert_eq!(value_of("x=1", "ret="), None);

        let headers = [
            "SVPNNETWORKCOOKIE=; path=/",
            "SVPNCOOKIE=; Path=/",
            "SVPNCOOKIE=abc; Path=/; Secure",
        ];
        let cookie = cookie_in(headers.into_iter()).expect("cookie");
        assert_eq!(cookie.expose_secret(), "SVPNCOOKIE=abc");
        assert!(is_cookie(&cookie));
        assert!(!is_cookie(&SecretString::from("abc")));
        assert!(!is_cookie(&SecretString::from("SVPNCOOKIE=")));
        for given in ["abc", "SVPNCOOKIE=abc", " SVPNCOOKIE=abc; Path=/\n"] {
            assert_eq!(normalize_cookie(given).expose_secret(), "SVPNCOOKIE=abc");
        }
    }

    #[test]
    fn finds_the_host_check_action() {
        assert_eq!(
            action_url("<form action=\"/remote/hostcheck_validate\" method=post>"),
            Some("/remote/hostcheck_validate".into())
        );
        assert_eq!(action_url("ret=1"), None);
    }

    #[test]
    fn parses_otp_forms() {
        let page = "HTML\n<html><FORM ACTION=\"/remote/logincheck\" METHOD=\"POST\">\
                    Please enter your token code<br>\
                    <INPUT TYPE=\"hidden\" NAME=\"username\" VALUE=\"alice\">\
                    <input type='hidden' name='magic' value='4tinet2095866395'>\
                    <INPUT TYPE=\"password\" NAME=\"credential2\" SIZE=\"25\">\
                    <INPUT TYPE=\"submit\" VALUE=\"Login\"></FORM>";
        let form = OtpForm::parse(page, None).expect("form");
        assert_eq!(
            form,
            OtpForm {
                action: "/remote/logincheck".into(),
                prompt: "Please enter your token code".into(),
                hidden: vec!["username=alice".into(), "magic=4tinet2095866395".into()],
                password: "credential2".into(),
            }
        );
        let form = OtpForm::parse(page, Some("token")).expect("form");
        assert_eq!(form.prompt, "token code");
        assert!(OtpForm::parse("<html>no form</html>", None).is_none());
    }

    #[test]
    fn parses_the_xml_configuration() {
        let xml = "<?xml version='1.0' encoding='utf-8'?>\
            <sslvpn-tunnel ver='2' dtls='0'><ipv4>\
            <dns ip='10.0.0.53'/><dns ip='10.0.0.54' domain='corp.example;lab.example'/>\
            <split-dns domains='x'/>\
            <assigned-addr ipv4='10.10.0.5'/>\
            <split-tunnel-info>\
            <addr ip='10.0.0.0' mask='255.0.0.0'/>\
            <addr ip='192.168.1.0' mask='255.255.255.0'/>\
            </split-tunnel-info></ipv4></sslvpn-tunnel>";
        let config = parse_vpn_config(xml).expect("config");
        assert_eq!(config.address, Some(Ipv4Addr::new(10, 10, 0, 5)));
        assert_eq!(
            config.dns,
            [Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)]
        );
        assert_eq!(config.domains, ["corp.example", "lab.example"]);
        assert_eq!(
            config.routes,
            [
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(192, 168, 1, 0), 24)
            ]
        );
        let full =
            parse_vpn_config("<ipv4><assigned-addr ipv4=\"10.1.1.1\"/></ipv4>").expect("config");
        assert!(full.routes.is_empty() && full.dns.is_empty());
        assert!(parse_vpn_config("<addr ip='10.0.0.0' mask='255.0.255.0'/>").is_ok());
        assert!(
            parse_vpn_config(
                "<split-tunnel-info><addr ip='10.0.0.0' mask='255.0.255.0'/></split-tunnel-info>"
            )
            .is_err()
        );
    }
}
