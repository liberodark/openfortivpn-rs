use std::net::Ipv4Addr;

use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::{Error, Result};

/// A point-to-point TUN device carrying raw IP packets.
pub struct Tun {
    device: AsyncDevice,
    name: String,
}

impl Tun {
    /// Creates the device with `address` on our side, `peer` on the
    /// gateway side for a point-to-point link, and brings it up.
    pub fn create(
        name: Option<&str>,
        address: Ipv4Addr,
        peer: Option<Ipv4Addr>,
        mtu: u16,
    ) -> Result<Self> {
        let mut builder = DeviceBuilder::new().mtu(mtu).ipv4(address, 32, peer);
        if let Some(name) = name {
            builder = builder.name(name);
        }
        let device = builder.build_async().map_err(Error::Tun)?;
        let name = device.name().map_err(Error::Tun)?;
        tracing::debug!("created TUN device {name}: {address} (peer {peer:?}), MTU {mtu}");
        Ok(Self { device, name })
    }

    /// The interface name (`tun0`, `utun3`...).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reads one IP packet.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.device.recv(buf).await
    }

    /// Writes one IP packet.
    pub async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        self.device.send(packet).await
    }
}
