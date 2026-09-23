//! No specification: what FortiClient tells a FortiGate about itself, as seen
//! in FortiOS's IKE debug log.

use std::net::Ipv4Addr;

use crate::message::payload::{Notify, notify};

/// The FortiClient version the gateway is told; FortiOS wants 7.2.4 or
/// later for the SAML login of IPsec VPNs.
const VERSION: &str = "7.4.8.1904";

/// The device FortiClient claims to be.
pub struct Device {
    /// The identifier the SAML login was requested with, which is also
    /// the EAP identity.
    pub uid: String,
}

impl Device {
    /// The vendor IDs FortiClient sends in IKE_SA_INIT, which FortiOS
    /// logs as "forticlient connect license", "Fortinet Endpoint Control"
    /// and an unknown one.
    pub const VENDOR_IDS: [[u8; 16]; 3] = [
        [
            0x4C, 0x53, 0x42, 0x7B, 0x6D, 0x46, 0x5D, 0x1B, 0x33, 0x7B, 0xB7, 0x55, 0xA3, 0x7A,
            0x7F, 0xEF,
        ],
        [
            0xB4, 0xF0, 0x1C, 0xA9, 0x51, 0xE9, 0xDA, 0x8D, 0x0B, 0xAF, 0xBB, 0xD3, 0x4A, 0xD3,
            0x04, 0x4E,
        ],
        [
            0xC1, 0xDC, 0x43, 0x50, 0x47, 0x6B, 0x98, 0xA4, 0x29, 0xB9, 0x17, 0x81, 0x91, 0x4C,
            0xA4, 0x3E,
        ],
    ];

    /// The FORTICLIENT_CONNECT notification for this device connecting
    /// from `address`.
    pub fn connect_notify(&self, address: Ipv4Addr) -> Notify {
        let hostname = nix::unistd::gethostname()
            .ok()
            .and_then(|name| name.into_string().ok())
            .unwrap_or_default();
        let user = std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_default();
        let os = nix::sys::utsname::uname()
            .map(|name| {
                format!(
                    "{} {}",
                    name.sysname().to_string_lossy(),
                    name.release().to_string_lossy()
                )
            })
            .unwrap_or_default();
        let info = format!(
            "VER=1\nFCTVER={VERSION}\nUID={}\nIP={address}\nHOST={hostname}\nUSER={user}\n\
             OSVER={os}\nREG_STATUS=0\nEMSSN=\nEMSID=\nFCTTAGS=1\n",
            self.uid
        );
        Notify::new(notify::FORTICLIENT_CONNECT, info.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_the_client() {
        let device = Device {
            uid: "0123456789ABCDEF0123456789ABCDEF".into(),
        };
        let notify = device.connect_notify(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(notify.kind, notify::FORTICLIENT_CONNECT);
        let text = String::from_utf8(notify.data).expect("text");
        assert!(text.starts_with(
            "VER=1\nFCTVER=7.4.8.1904\nUID=0123456789ABCDEF0123456789ABCDEF\nIP=10.0.0.2\nHOST="
        ));
        assert!(text.ends_with("\nREG_STATUS=0\nEMSSN=\nEMSID=\nFCTTAGS=1\n"));
    }
}
