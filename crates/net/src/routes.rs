use std::net::Ipv4Addr;

use crate::command::{already_exists, run};
use crate::{Error, Result};

/// The default route as it was before the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRoute {
    gateway: Option<Ipv4Addr>,
    interface: String,
    #[cfg(target_os = "linux")]
    metric: Option<u32>,
}

/// A network sent into the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Network {
    address: Ipv4Addr,
    prefix: u8,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// The routes installed for a tunnel interface, removed by
/// [`Routes::restore`].
#[derive(Debug)]
pub struct Routes {
    interface: String,
    /// Host route to the VPN gateway we added.
    gateway: Option<Ipv4Addr>,
    /// Networks routed into the tunnel.
    networks: Vec<Network>,
    /// The default route we replaced.
    replaced_default: Option<DefaultRoute>,
}

impl Routes {
    /// Tracks the routes of the tunnel `interface`.
    #[must_use]
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            gateway: None,
            networks: Vec::new(),
            replaced_default: None,
        }
    }

    /// Pins the route to the VPN gateway on the current path, so that the
    /// tunnel traffic itself does not go into the tunnel once the default
    /// route points there. Fails when the gateway is left unprotected.
    pub async fn protect_gateway(&mut self, gateway: Ipv4Addr) -> Result<()> {
        let mut current = self.current_route_to(gateway).await?;
        if current.interface == self.interface {
            // A gateway that gives its own public address as the peer
            // address of the link gets a kernel route through the tunnel,
            // which would swallow the tunnel itself. openfortivpn drops it
            // too ("wrongly configured pppd with ip-accept-remote").
            tracing::warn!("Removing wrong route to vpn server...");
            self.delete_host_via(gateway, &self.interface.clone())
                .await?;
            current = self.current_route_to(gateway).await?;
            if current.interface == self.interface {
                return Err(Error::Command {
                    command: "route".into(),
                    stderr: format!("{gateway} is still routed through {}", self.interface),
                });
            }
        }
        tracing::debug!("pinning the route to the gateway {gateway} through {current:?}");
        match self.add_host(gateway, &current).await {
            Ok(()) => self.gateway = Some(gateway),
            Err(error) if already_exists(&error) => {
                tracing::warn!("Route to the VPN gateway exists already.");
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Sends all traffic into the tunnel: replaces the default route, or
    /// with `half`, adds two more specific routes covering everything.
    pub async fn set_default(&mut self, half: bool) -> Result<()> {
        if half {
            for address in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(128, 0, 0, 0)] {
                self.add(address, 1).await?;
            }
            return Ok(());
        }
        self.replace_default().await
    }

    /// Sends one network into the tunnel.
    pub async fn add(&mut self, address: Ipv4Addr, prefix: u8) -> Result<()> {
        let network = Network { address, prefix };
        match self.add_network(network).await {
            Ok(()) => self.networks.push(network),
            Err(error) if already_exists(&error) => {
                let existing = self
                    .existing_route(network)
                    .await
                    .map_or_else(String::new, |route| format!(" ({route})"));
                tracing::warn!("Route {network} exists already{existing}.");
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Puts the routing table back.
    pub async fn restore(&mut self) {
        for network in std::mem::take(&mut self.networks) {
            if let Err(error) = self.delete_network(network).await {
                tracing::debug!("could not delete route {network}: {error}");
            }
        }
        if let Some(default) = self.replaced_default.take()
            && let Err(error) = self.put_default_back(&default).await
        {
            tracing::warn!("Could not restore the default route ({error}).");
        }
        if let Some(gateway) = self.gateway.take()
            && let Err(error) = self.delete_host(gateway).await
        {
            tracing::debug!("could not delete the route to the gateway: {error}");
        }
    }
}

#[cfg(target_os = "linux")]
impl Routes {
    async fn current_route_to(&self, destination: Ipv4Addr) -> Result<DefaultRoute> {
        let output = run(
            "ip",
            &["-4", "route", "get", &destination.to_string()],
            None,
        )
        .await?;
        parse_ip_route(&output).ok_or(Error::Parse {
            command: "ip route get".into(),
            output,
        })
    }

    async fn add_host(&self, gateway: Ipv4Addr, via: &DefaultRoute) -> Result<()> {
        let host = format!("{gateway}/32");
        let mut args = vec!["route", "add", host.as_str()];
        let hop;
        if let Some(next_hop) = via.gateway {
            hop = next_hop.to_string();
            args.extend(["via", hop.as_str()]);
        }
        args.extend(["dev", via.interface.as_str()]);
        run("ip", &args, None).await.map(drop)
    }

    async fn delete_host(&self, gateway: Ipv4Addr) -> Result<()> {
        run("ip", &["route", "del", &format!("{gateway}/32")], None)
            .await
            .map(drop)
    }

    async fn delete_host_via(&self, gateway: Ipv4Addr, interface: &str) -> Result<()> {
        run(
            "ip",
            &["route", "del", &format!("{gateway}/32"), "dev", interface],
            None,
        )
        .await
        .map(drop)
    }

    /// Describes the route that already covers `network`.
    async fn existing_route(&self, network: Network) -> Option<String> {
        let output = run("ip", &["-4", "route", "show", &network.to_string()], None)
            .await
            .ok()?;
        let line = output.lines().next()?.trim();
        (!line.is_empty()).then(|| line.to_owned())
    }

    async fn add_network(&self, network: Network) -> Result<()> {
        run(
            "ip",
            &["route", "add", &network.to_string(), "dev", &self.interface],
            None,
        )
        .await
        .map(drop)
    }

    async fn delete_network(&self, network: Network) -> Result<()> {
        run(
            "ip",
            &["route", "del", &network.to_string(), "dev", &self.interface],
            None,
        )
        .await
        .map(drop)
    }

    /// Adds a default route through the tunnel with the best metric. When a
    /// metric-0 default route already exists, replaces it and remembers it.
    async fn replace_default(&mut self) -> Result<()> {
        match run(
            "ip",
            &["route", "add", "default", "dev", &self.interface],
            None,
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(error) if already_exists(&error) => {}
            Err(error) => return Err(error),
        }
        let output = run("ip", &["-4", "route", "show", "default"], None).await?;
        let current = output
            .lines()
            .find_map(parse_ip_route)
            .ok_or(Error::Parse {
                command: "ip route show default".into(),
                output: output.clone(),
            })?;
        tracing::debug!("replacing the default route {current:?}");
        run(
            "ip",
            &["route", "replace", "default", "dev", &self.interface],
            None,
        )
        .await?;
        self.replaced_default = Some(current);
        Ok(())
    }

    async fn put_default_back(&self, default: &DefaultRoute) -> Result<()> {
        let mut args = vec!["route", "replace", "default"];
        let hop;
        if let Some(gateway) = default.gateway {
            hop = gateway.to_string();
            args.extend(["via", hop.as_str()]);
        }
        args.extend(["dev", default.interface.as_str()]);
        let metric;
        if let Some(value) = default.metric {
            metric = value.to_string();
            args.extend(["metric", metric.as_str()]);
        }
        run("ip", &args, None).await.map(drop)
    }
}

/// Parses one line of `ip route` output: `... via <gw> dev <if> ... metric <m>`.
#[cfg(target_os = "linux")]
fn parse_ip_route(line: &str) -> Option<DefaultRoute> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let value_after = |key: &str| {
        words
            .iter()
            .position(|word| *word == key)
            .and_then(|index| words.get(index + 1).copied())
    };
    Some(DefaultRoute {
        gateway: value_after("via").and_then(|gateway| gateway.parse().ok()),
        interface: value_after("dev")?.to_owned(),
        metric: value_after("metric").and_then(|metric| metric.parse().ok()),
    })
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl Routes {
    async fn current_route_to(&self, destination: Ipv4Addr) -> Result<DefaultRoute> {
        let output = run("route", &["-n", "get", &destination.to_string()], None).await?;
        parse_route_get(&output).ok_or(Error::Parse {
            command: "route get".into(),
            output,
        })
    }

    async fn add_host(&self, gateway: Ipv4Addr, via: &DefaultRoute) -> Result<()> {
        let host = gateway.to_string();
        let hop = via.gateway.map(|hop| hop.to_string());
        let args = match &hop {
            Some(hop) => vec!["-n", "add", "-host", host.as_str(), hop.as_str()],
            None => vec![
                "-n",
                "add",
                "-host",
                host.as_str(),
                "-interface",
                via.interface.as_str(),
            ],
        };
        run("route", &args, None).await.map(drop)
    }

    async fn delete_host(&self, gateway: Ipv4Addr) -> Result<()> {
        run(
            "route",
            &["-n", "delete", "-host", &gateway.to_string()],
            None,
        )
        .await
        .map(drop)
    }

    async fn delete_host_via(&self, gateway: Ipv4Addr, interface: &str) -> Result<()> {
        run(
            "route",
            &[
                "-n",
                "delete",
                "-host",
                &gateway.to_string(),
                "-interface",
                interface,
            ],
            None,
        )
        .await
        .map(drop)
    }

    /// Describes the route that already covers `network`.
    async fn existing_route(&self, network: Network) -> Option<String> {
        let output = run("route", &["-n", "get", &network.to_string()], None)
            .await
            .ok()?;
        let route = parse_route_get(&output)?;
        Some(match route.gateway {
            Some(gateway) => format!("via {gateway} dev {}", route.interface),
            None => format!("dev {}", route.interface),
        })
    }

    async fn add_network(&self, network: Network) -> Result<()> {
        run(
            "route",
            &[
                "-n",
                "add",
                "-net",
                &network.to_string(),
                "-interface",
                &self.interface,
            ],
            None,
        )
        .await
        .map(drop)
    }

    async fn delete_network(&self, network: Network) -> Result<()> {
        run(
            "route",
            &["-n", "delete", "-net", &network.to_string()],
            None,
        )
        .await
        .map(drop)
    }

    async fn replace_default(&mut self) -> Result<()> {
        let output = run("route", &["-n", "get", "default"], None).await?;
        let current = parse_route_get(&output).ok_or(Error::Parse {
            command: "route get default".into(),
            output: output.clone(),
        })?;
        tracing::debug!("replacing the default route {current:?}");
        run("route", &["-n", "delete", "default"], None).await?;
        self.replaced_default = Some(current);
        run(
            "route",
            &["-n", "add", "default", "-interface", &self.interface],
            None,
        )
        .await
        .map(drop)
    }

    async fn put_default_back(&self, default: &DefaultRoute) -> Result<()> {
        run("route", &["-n", "delete", "default"], None).await.ok();
        let hop = default.gateway.map(|hop| hop.to_string());
        let args = match &hop {
            Some(hop) => vec!["-n", "add", "default", hop.as_str()],
            None => vec![
                "-n",
                "add",
                "default",
                "-interface",
                default.interface.as_str(),
            ],
        };
        run("route", &args, None).await.map(drop)
    }
}

/// Parses `route -n get` output: `gateway: <gw>` and `interface: <if>` lines.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn parse_route_get(output: &str) -> Option<DefaultRoute> {
    let field = |name: &str| {
        output.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then(|| value.trim().to_owned())
        })
    };
    Some(DefaultRoute {
        gateway: field("gateway").and_then(|gateway| gateway.parse().ok()),
        interface: field("interface")?,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_route_lines() {
        let route =
            parse_ip_route("default via 192.0.2.1 dev eth0 proto dhcp metric 100").expect("route");
        assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(route.interface, "eth0");
        assert_eq!(route.metric, Some(100));
        let route = parse_ip_route("10.99.0.2 dev ofv-host src 10.99.0.1 uid 0").expect("route");
        assert_eq!(route.gateway, None);
        assert_eq!(route.interface, "ofv-host");
        assert_eq!(route.metric, None);
        assert!(parse_ip_route("local 127.0.0.1 src 127.0.0.1").is_none());
    }
}
