# openfortivpn-rs

A Rust client for Fortinet VPN gateways, keeping the command line and the
configuration file of [openfortivpn](https://github.com/adrienverge/openfortivpn).

Two protocols:

- **SSL VPN** (the default, as in openfortivpn): the VPN a FortiGate exposes to
  FortiClient's "SSL-VPN", PPP over TLS. Implemented natively: no `pppd`, no
  OpenSSL. The TLS client is [rustls](https://github.com/rustls/rustls), the
  PPP link (LCP, IPCP) is negotiated here and the IP packets go through a TUN
  device with the routes and nameservers pushed by the gateway.
- **IKEv2/IPsec** (`--protocol=ipsec`): the VPN a FortiGate exposes to
  FortiClient's "IPsec VPN". Implemented natively too: IKEv2 (RFC 7296) with
  EAP-MSCHAPv2/GTC/MD5, pre-shared key or certificate authentication, the
  configuration payload (virtual IP, DNS, split networks), rekeys, dead peer
  detection, and ESP carried in userspace over UDP port 4500 into the same TUN
  device. No kernel IPsec stack and no daemon are needed; a running
  [strongSwan](https://strongswan.org) daemon (`charon`) can still be used
  instead with `--ipsec-backend=charon`.

Linux, macOS and FreeBSD, like openfortivpn.

## Layout

| Crate | Content |
|---|---|
| `crates/sslvpn` (`ofv-sslvpn`) | The SSL VPN: TLS connection (`tls.rs`), minimal HTTP client (`http.rs`), portal login with one-time passwords, two-factor tokens, FortiToken push, SAML and client certificates (`portal.rs`, `saml.rs`), the PPP automaton as a sans-I/O state machine (`ppp.rs`), the tunnel life cycle (`tunnel.rs`). |
| `crates/https` (`ofv-https`) | The web side of a gateway, shared by both modes: TLS connections with rustls (`tls.rs`: system roots or `ca-file`, `trusted-cert` digests, client certificate, `https_proxy`, `ifname`), a minimal HTTP/1.1 client (`http.rs`), the local server receiving a browser's redirect after a SAML login (`redirect.rs`). |
| `crates/net` (`ofv-net`) | The host side shared by the tunnels that carry IP themselves: TUN device (`tun-rs`), routes (`ip` / `route`), nameservers (`resolvconf` or `/etc/resolv.conf`), all put back on exit. |
| `crates/pki` (`ofv-pki`) | PEM certificates and private keys (PKCS#8, PKCS#1, SEC1, encrypted PKCS#8). |
| `crates/ikev2` (`ofv-ikev2`) | The native IKEv2/IPsec client: message codec (`message/`), cryptography with the RustCrypto crates (`crypto/`: DH groups, PRFs, ciphers, signatures, MS-CHAPv2), the IKE SA and its keys (`sa.rs`), the CHILD SAs and ESP (`child.rs`), EAP (`eap.rs`), gateway certificates (`auth.rs`), FortiClient's SAML login (`saml.rs`), the exchanges (`setup.rs`, `rekey.rs`) and the session with the UDP transport, retransmissions, the gateway's requests and the tunnel traffic (`session.rs`). |
| `crates/vici` (`ofv-vici`) | Self-contained client for strongSwan's vici protocol (Tokio, cancel-safe). |
| `crates/charon` (`ofv-charon`) | The IPsec tunnel through a strongSwan charon daemon (the `charon` backend): credentials, connection, initiation, events, teardown. |
| `crates/cli` (`openfortivpn-rs`) | Command line and configuration file (openfortivpn's `key = value` format), secret prompts (terminal or pinentry), signals, `--persistent` loop. |

## SSL VPN

```sh
sudo openfortivpn-rs vpn-gateway[:port] -u alice            # asks the password
sudo openfortivpn-rs -c /etc/openfortivpn/config            # the default file
sudo openfortivpn-rs vpn-gateway --saml-login               # SAML in a browser
sudo openfortivpn-rs vpn-gateway --cookie-on-stdin < cookie
```

The configuration file is openfortivpn's, with the same option names:

```ini
host = vpn-gateway
port = 443
username = alice
# password = ...                  # asked on the terminal (or by pinentry) if unset
# realm = ...
# otp = 123456                    # one-time password; asked when the gateway wants one
# otp-prompt = Please enter       # text locating the prompt in the gateway's form
# otp-delay = 0
# no-ftm-push = 0                 # 1: never wait for a FortiToken Mobile push
# cookie = SVPNCOOKIE=...         # an existing session instead of a login
# saml-login = 8020               # local port receiving the SAML redirect
# trusted-cert = <sha256 hex>     # accept this gateway certificate (repeatable)
# ca-file = /path/to/ca.pem       # roots for the gateway certificate
# user-cert = /path/to/cert.pem   # client certificate...
# user-key = /path/to/key.pem     # ...and key (PKCS#8 encrypted keys supported)
# pem-passphrase = ...
# sni = ...                       # server name for the TLS handshake
# min-tls = 1.2                   # or 1.3
# set-routes = 1                  # 0: do not touch the routing table
# half-internet-routes = 0        # 1: two /1 routes instead of the default route
# set-dns = 1                     # 0: do not touch the resolver
# use-resolvconf = 1              # resolvconf/resolvectl when available; 0: edit /etc/resolv.conf
# pppd-use-peerdns = 0            # 1: nameservers from IPCP rather than the XML
# pppd-ifname = fortivpn          # name of the TUN interface
# ifname = eth0                   # send the tunnel through this interface
# user-agent = Mozilla/5.0 SV1
# hostcheck = ...                 # answers to the gateway's host check
# check-virtual-desktop = ...
# pinentry = pinentry-curses
# persistent = 10                 # reconnect after 10 s when the tunnel drops
```

How it works, in the order openfortivpn does it: TLS handshake (the gateway
certificate is checked against the system roots or `ca-file` and the host
name, or accepted by SHA-256 digest with `trusted-cert`); `POST
/remote/logincheck` with the credentials, then the one-time password form, the
two-factor token (`tokeninfo`), the FortiToken push (`ftmpush=1`) or the SAML
session (`/remote/saml/auth_id`) as the gateway asks; `GET /remote/index`,
`GET /remote/fortisslvpn`, a new TLS connection, `GET /remote/fortisslvpn_xml`
(assigned address, nameservers, search domains, split routes); `GET
/remote/sslvpn-tunnel` after which the connection carries PPP packets framed
as `[length][0x5050][length]`. LCP is negotiated with openfortivpn's pppd
options (`noauth noaccomp nopcomp mru 1354`), then IPCP (`noipdefault
ipcp-accept-local ipcp-accept-remote`); a TUN device gets the addresses, the
routes (the gateway pinned on its current path — a FortiGate often gives its
own address as the PPP peer, the kernel route this creates through the tunnel
is dropped like openfortivpn does — then the split routes or the default
route) and the resolver settings: through `resolvconf` when installed
(openresolv, Debian's resolvconf, systemd-resolved's compatibility command),
`resolvectl` on a systemd-resolved system without it, or by editing
`/etc/resolv.conf` (`use-resolvconf = 0` forces the latter). On exit, or when
the gateway closes the link, everything is put back, the PPP link is
terminated and the session is logged out.

Differences with openfortivpn:

- No `pppd`: the `pppd-*` options are accepted but only `pppd-use-peerdns`
  (`pppd-no-peerdns`) and `pppd-ifname` have an effect.
- TLS 1.2 and 1.3 only, with rustls's cipher suites: `insecure-ssl`,
  `cipher-list`, `seclevel-1` and `min-tls = 1.0`/`1.1` are accepted with a
  warning. Gateways that only speak TLS 1.0/1.1 are not reachable.
- Smartcards (`pkcs11:` URIs) and `use-syslog` are not supported.
- A bad line or value in the configuration file is an error, not a warning.

## IPsec

```sh
sudo openfortivpn-rs vpn-gateway --protocol=ipsec -u alice   # asks the password and the PSK
sudo openfortivpn-rs vpn-gateway --protocol=ipsec --saml-login   # SAML in a browser
```

```ini
protocol = ipsec
host = vpn-gateway
username = alice
ipsec-psk = the-pre-shared-key
# ipsec-auth = eap-mschapv2        # eap-gtc, eap-md5, psk, pubkey
# ipsec-local-id = my-peer-id      # FortiClient "Local ID" (@@id for a KEY_ID)
# ipsec-remote-id = vpn.example.com
# ipsec-split-include = 10.0.0.0/8,192.168.10.0/24
# ipsec-ike-proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
# ipsec-esp-proposals = aes256-sha256-modp2048,aes128-sha256
# ipsec-dpd-delay = 30
# saml-login = 1                   # or the local redirect port; FortiOS "ike-saml-server"
# ipsec-saml-port = 1001           # the FortiGate's auth-ike-saml-port
# trusted-cert = <sha256>          # of the certificate on that port, unless publicly trusted
# ipsec-backend = native           # or charon (strongSwan)
# ipsec-vici-socket = /run/charon.vici   # charon backend
# ipsec-udp-encap = 0                    # charon backend; always on natively
```

| FortiClient / FortiGate | Configuration |
|---|---|
| Remote Gateway | `host` (port 500 unless `port` is set) |
| Pre-shared Key | `ipsec-psk` |
| User name / password (`set eap enable`) | `username`, `password`, `ipsec-auth = eap-mschapv2` (default) |
| X.509 certificate (`set authmethod signature`) | `ipsec-auth = pubkey`, `user-cert`, `user-key`, `ca-file` |
| Local ID (`set peerid`) | `ipsec-local-id` |
| SAML (`set ike-saml-server` on the interface) | `saml-login`, with `ipsec-saml-port` = the FortiGate's `auth-ike-saml-port` if not 1001 |
| Split tunnel networks | negotiated from the phase 2 selectors, or `ipsec-split-include` |

The native backend (the default) talks IKEv2 itself: IKE_SA_INIT with a
cookie or group change if the gateway asks, IKE_AUTH with the EAP rounds, the
configuration payload, one CHILD SA per split network the gateway does not
cover, then ESP in UDP (RFC 3948, always, as FortiClient does behind NAT: the
gateway must have NAT traversal enabled, which is the default) into a TUN
device with the routes and nameservers of the SSL VPN mode (`set-routes`,
`set-dns`, `use-resolvconf`, `pppd-ifname` apply). Gateway certificates are
checked against `ca-file` or the system roots, and against `ipsec-remote-id`
or the host name; RSA keys, ours and the gateway's, must be 2048 bits or
more, and an RSA key of ours signs with SHA-2 only, which needs a gateway
taking RFC 7427 signatures (any FortiGate does). It answers the gateway's dead peer detection, CHILD SA and
IKE SA rekeys, rekeys its CHILD SAs itself, and reconnects with `persistent`.
The proposals use strongSwan's names: AES-CBC/GCM 128/256, ChaCha20-Poly1305,
SHA-1/256/384/512, MODP 1024–4096, ECP 256/384/521, Curve25519.

`--saml-login` does what FortiClient does for a SAML-authenticated IPsec VPN
(FortiOS 7.2+, `set ike-saml-server` on the interface): it asks the gateway
(`POST /saml_login?` over HTTPS on its `auth-ike-saml-port`, 1001 unless
`ipsec-saml-port` says otherwise) for the login URL with a random device
identifier, prints the URL for the browser, receives the browser back on the
local port (8020, or `--saml-login=PORT`) with the user name and a token, then
presents itself as FortiClient in IKE (its vendor IDs in IKE_SA_INIT, a
FORTICLIENT_CONNECT notification with the device identifier in IKE_AUTH) and
runs the EAP exchange the way FortiClient does: the device identifier is the
EAP identity, which is how the gateway finds the SAML session, and the token
the password. The gateway then checks the SAML user against the group of the
phase 1 (`set authusrgrp`) or of the firewall policy, and refuses the EAP
exchange when the user is not a member. The certificate on the SAML port
(often the FortiGate's factory one) is checked against the system roots or
`trusted-cert`; `ca-file` also makes the IKE side expect a gateway
certificate, so keep it for gateways that authenticate with one.

With `ipsec-backend = charon`, a running strongSwan with its `vici` plugin and
the EAP plugins does the work instead (`apt install strongswan-swanctl
charon-systemd libcharon-extra-plugins`, `brew install strongswan`, ...); no
`swanctl.conf` is needed, the connection is loaded at run time and removed on
exit, and charon installs the virtual IP, routes and DNS servers itself
(`swanctl --list-sas` shows the tunnel state, `-v` relays its log). Not
supported by either backend: IKEv1, EMS/ZTNA registration, smartcards (the
charon backend can use its `pkcs11` plugin), IPv6; the SAML login is native
only.

## Standards

Each source file names at its top the specifications it implements (RFC
1661/1332/1877 for PPP, RFC 7296 and its companions for IKEv2, RFC 4303 and
RFC 3948 for ESP, RFC 3748 and RFC 2759 for EAP, and so on), or where the
behaviour comes from when there is none (the FortiGate portal, FortiClient's
SAML login); the code cites the section it follows at the relevant spot.

## Building and testing

```sh
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets   # warnings are errors in CI
cargo audit
```
