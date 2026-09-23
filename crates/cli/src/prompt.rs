//! Assuan (the GnuPG pinentry protocol).

use std::fmt::Write as _;
use std::process::Stdio;

use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use zeroize::Zeroizing;

/// Why no secret could be obtained.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not read from the terminal: {0}")]
    Terminal(std::io::Error),
    #[error("could not run {program}: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("pinentry: {0}")]
    Pinentry(String),
}

/// Asks for a secret, through `pinentry` when one is configured.
pub async fn secret(
    pinentry: Option<&str>,
    key_info: &str,
    prompt: &str,
) -> Result<SecretString, Error> {
    if let Some(program) = pinentry.filter(|program| !program.is_empty()) {
        return from_pinentry(program, key_info, prompt).await;
    }
    // Off the runtime thread, so that signals are still handled while the
    // user types.
    let prompt = format!("{prompt} ");
    tokio::task::spawn_blocking(move || rpassword::prompt_password(prompt))
        .await
        .map_err(|error| Error::Terminal(std::io::Error::other(error)))?
        .map(SecretString::from)
        .map_err(Error::Terminal)
}

async fn from_pinentry(program: &str, key_info: &str, prompt: &str) -> Result<SecretString, Error> {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|source| Error::Spawn {
            program: program.to_owned(),
            source,
        })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::Pinentry("no stdin".into()))?;
    let mut stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| Error::Pinentry("no stdout".into()))?,
    );

    let mut session = Assuan {
        input: &mut stdout,
        output: &mut stdin,
    };
    // The greeting.
    session.read_response().await?;
    session.command("SETTITLE VPN Password").await?;
    session.command("SETDESC VPN Requires a Password").await?;
    session
        .command(&format!("SETKEYINFO {}", escape(key_info)))
        .await?;
    session
        .command(&format!("SETPROMPT {}", escape(prompt)))
        .await?;
    let pin = session.command("GETPIN").await?;
    drop(stdin);
    child.wait().await.ok();
    pin.ok_or_else(|| Error::Pinentry("no password given".into()))
}

struct Assuan<'a, R, W> {
    input: &'a mut R,
    output: &'a mut W,
}

impl<R: AsyncBufReadExt + Unpin, W: AsyncWriteExt + Unpin> Assuan<'_, R, W> {
    /// Sends a command and returns the data line of its response, if any.
    async fn command(&mut self, command: &str) -> Result<Option<SecretString>, Error> {
        self.output
            .write_all(format!("{command}\n").as_bytes())
            .await
            .map_err(|error| Error::Pinentry(error.to_string()))?;
        self.read_response().await
    }

    /// Reads lines until `OK` or `ERR`, keeping the `D` data line.
    async fn read_response(&mut self) -> Result<Option<SecretString>, Error> {
        let mut data = None;
        loop {
            let mut line = Zeroizing::new(String::new());
            let read = self
                .input
                .read_line(&mut line)
                .await
                .map_err(|error| Error::Pinentry(error.to_string()))?;
            if read == 0 {
                return Err(Error::Pinentry("connection closed".into()));
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line == "OK" || line.starts_with("OK ") {
                return Ok(data);
            }
            if let Some(payload) = line.strip_prefix("D ") {
                data = Some(SecretString::from(unescape(payload).as_str()));
            } else if line.starts_with("ERR ") || line.starts_with("S ERROR") {
                return Err(Error::Pinentry(line.to_owned()));
            }
            // Comments ("#") and status lines ("S ...") are skipped.
        }
    }
}

/// Percent-encodes everything but unreserved characters, as the C client
/// does for key info and prompts.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            let _ = write!(escaped, "%{byte:02X}");
        }
    }
    escaped
}

/// Decodes the `%XX` escapes of an Assuan data line.
fn unescape(text: &str) -> Zeroizing<String> {
    let bytes = text.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        let decoded = (bytes[index] == b'%')
            .then(|| bytes.get(index + 1..index + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        if let Some(byte) = decoded {
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_the_c_client() {
        assert_eq!(escape("alice_gw.example~1"), "alice_gw.example~1");
        assert_eq!(
            escape("VPN account password: "),
            "VPN%20account%20password%3A%20"
        );
    }

    #[test]
    fn unescapes_data_lines() {
        assert_eq!(unescape("pass%25word%0A").as_str(), "pass%word\n");
        assert_eq!(unescape("plain").as_str(), "plain");
        assert_eq!(unescape("trailing%2").as_str(), "trailing%2");
    }
}
