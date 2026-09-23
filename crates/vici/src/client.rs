use std::collections::VecDeque;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::{Error, MESSAGE_SIZE_MAX, Packet, Result, Section};

/// An event raised by charon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Event name, e.g. `ike-updown`.
    pub name: String,
    pub message: Section,
}

/// A connection to charon's vici socket.
///
/// Only one command can be in flight per connection and charon does not
/// number its responses, so a request future dropped half-way (cancelled)
/// leaves the stream in an unknown state: the client then refuses further
/// use with [`Error::Poisoned`] and must be dropped. Waiting for events with
/// [`Client::next_event`] is cancel-safe.
pub struct Client {
    stream: UnixStream,
    /// Bytes received but not yet parsed into a packet.
    buf: Vec<u8>,
    /// Events received while a command or registration was in progress.
    pending: VecDeque<Event>,
    poisoned: bool,
}

impl Client {
    /// Connects to the vici Unix socket at `path`.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self {
            stream,
            buf: Vec::new(),
            pending: VecDeque::new(),
            poisoned: false,
        })
    }

    /// Sends a command and waits for its response. Events received in the
    /// meantime are queued for [`Client::next_event`].
    pub async fn request(&mut self, command: &str, message: Section) -> Result<Section> {
        self.exchange(command, message, None).await
    }

    /// Sends a command and waits for its response, handing the events
    /// received in the meantime (for instance `control-log`) to `on_event`
    /// as they arrive.
    pub async fn request_with(
        &mut self,
        command: &str,
        message: Section,
        on_event: &mut dyn FnMut(Event),
    ) -> Result<Section> {
        self.exchange(command, message, Some(on_event)).await
    }

    pub async fn register(&mut self, event: &str) -> Result<()> {
        self.subscribe(Packet::EventRegister(event.to_owned()), event)
            .await
    }

    pub async fn unregister(&mut self, event: &str) -> Result<()> {
        self.subscribe(Packet::EventUnregister(event.to_owned()), event)
            .await
    }

    /// Waits for the next event. Cancel-safe.
    pub async fn next_event(&mut self) -> Result<Event> {
        self.check()?;
        if let Some(event) = self.pending.pop_front() {
            return Ok(event);
        }
        match self.read_packet().await? {
            Packet::Event { name, message } => Ok(Event { name, message }),
            _ => Err(Error::UnexpectedPacket),
        }
    }

    fn check(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }

    async fn exchange(
        &mut self,
        command: &str,
        message: Section,
        mut on_event: Option<&mut dyn FnMut(Event)>,
    ) -> Result<Section> {
        self.check()?;
        let bytes = Packet::CmdRequest {
            name: command.to_owned(),
            message,
        }
        .encode()?;
        self.poisoned = true;
        self.stream.write_all(&bytes).await?;
        let result = loop {
            match self.read_packet().await {
                Ok(Packet::Event { name, message }) => {
                    let event = Event { name, message };
                    match on_event.as_deref_mut() {
                        Some(callback) => callback(event),
                        None => self.pending.push_back(event),
                    }
                }
                Ok(Packet::CmdResponse(response)) => break Ok(response),
                Ok(Packet::CmdUnknown) => break Err(Error::UnknownCommand(command.to_owned())),
                Ok(_) => break Err(Error::UnexpectedPacket),
                Err(error) => break Err(error),
            }
        };
        self.poisoned = false;
        result
    }

    async fn subscribe(&mut self, packet: Packet, event: &str) -> Result<()> {
        self.check()?;
        let bytes = packet.encode()?;
        self.poisoned = true;
        self.stream.write_all(&bytes).await?;
        let result = loop {
            match self.read_packet().await {
                Ok(Packet::Event { name, message }) => {
                    self.pending.push_back(Event { name, message });
                }
                Ok(Packet::EventConfirm) => break Ok(()),
                Ok(Packet::EventUnknown) => break Err(Error::UnknownEvent(event.to_owned())),
                Ok(_) => break Err(Error::UnexpectedPacket),
                Err(error) => break Err(error),
            }
        };
        self.poisoned = false;
        result
    }

    /// Reads one packet. Cancel-safe: bytes already received stay in the
    /// buffer.
    async fn read_packet(&mut self) -> Result<Packet> {
        loop {
            if let Some(packet) = self.parse_buffered()? {
                return Ok(packet);
            }
            if self.stream.read_buf(&mut self.buf).await? == 0 {
                return Err(Error::Closed);
            }
        }
    }

    fn parse_buffered(&mut self) -> Result<Option<Packet>> {
        let Some(prefix) = self.buf.get(..4) else {
            return Ok(None);
        };
        let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        let len = usize::try_from(len).map_err(|_| Error::MessageSize(usize::MAX))?;
        if len == 0 || len > MESSAGE_SIZE_MAX {
            return Err(Error::MessageSize(len));
        }
        let total = 4 + len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let packet = Packet::decode(&self.buf[4..total])?;
        self.buf.drain(..total);
        Ok(Some(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::net::UnixListener;

    /// A fake charon answering "version", knowing the "ping" event and
    /// raising one event while answering "slow".
    async fn fake_charon(listener: UnixListener) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await.expect("read");
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
            while buf.len() >= 4 {
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if buf.len() < 4 + len {
                    break;
                }
                let packet = Packet::decode(&buf[4..4 + len]).expect("decode");
                buf.drain(..4 + len);
                let replies = match packet {
                    Packet::CmdRequest { name, .. } if name == "version" => {
                        vec![Packet::CmdResponse(Section::new().kv("version", "5.9.13"))]
                    }
                    Packet::CmdRequest { name, .. } if name == "slow" => vec![
                        Packet::Event {
                            name: "control-log".into(),
                            message: Section::new().kv("msg", "working"),
                        },
                        Packet::CmdResponse(Section::new().kv("success", "yes")),
                    ],
                    Packet::CmdRequest { .. } => vec![Packet::CmdUnknown],
                    Packet::EventRegister(name) | Packet::EventUnregister(name) => {
                        if name == "ping" {
                            vec![
                                Packet::EventConfirm,
                                Packet::Event {
                                    name: "ping".into(),
                                    message: Section::new().kv("n", "1"),
                                },
                            ]
                        } else {
                            vec![Packet::EventUnknown]
                        }
                    }
                    _ => vec![],
                };
                for reply in replies {
                    stream
                        .write_all(&reply.encode().expect("encode"))
                        .await
                        .expect("write");
                }
            }
        }
    }

    #[tokio::test]
    async fn talks_to_a_fake_charon() {
        let dir = std::env::temp_dir().join(format!("ofv-vici-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("charon.vici");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = tokio::spawn(fake_charon(listener));

        let mut client = Client::connect(&path).await.expect("connect");
        let version = client
            .request("version", Section::new())
            .await
            .expect("version");
        assert_eq!(version.get_str(&["version"]), Some("5.9.13"));

        assert!(matches!(
            client.request("nope", Section::new()).await,
            Err(Error::UnknownCommand(name)) if name == "nope"
        ));
        assert!(matches!(
            client.register("nope").await,
            Err(Error::UnknownEvent(name)) if name == "nope"
        ));

        client.register("ping").await.expect("register");
        let event = client.next_event().await.expect("event");
        assert_eq!(event.name, "ping");
        assert_eq!(event.message.get_str(&["n"]), Some("1"));

        let mut seen = Vec::new();
        let response = client
            .request_with("slow", Section::new(), &mut |event| seen.push(event.name))
            .await
            .expect("slow");
        assert_eq!(response.get_str(&["success"]), Some("yes"));
        assert_eq!(seen, ["control-log"]);

        drop(client);
        server.await.expect("server");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[tokio::test]
    async fn cancelled_request_poisons_the_client() {
        let dir = std::env::temp_dir().join(format!("ofv-vici-poison-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("charon.vici");
        let listener = UnixListener::bind(&path).expect("bind");
        // A charon that never answers.
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            drop(stream);
        });

        let mut client = Client::connect(&path).await.expect("connect");
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            client.request("version", Section::new()),
        )
        .await;
        assert!(cancelled.is_err());
        assert!(matches!(
            client.request("version", Section::new()).await,
            Err(Error::Poisoned)
        ));
        assert!(matches!(client.next_event().await, Err(Error::Poisoned)));

        server.abort();
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
