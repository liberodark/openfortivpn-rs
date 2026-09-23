use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::command::run;
use crate::{Error, Result};

const RESOLV_CONF: &str = "/etc/resolv.conf";
/// Where systemd-resolved keeps the files `/etc/resolv.conf` links to.
const RESOLVED_DIR: &str = "/run/systemd/resolve";

/// Which tool installs the DNS settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsTool {
    /// `resolvconf` when installed, `resolvectl` on systemd-resolved,
    /// `/etc/resolv.conf` otherwise.
    #[default]
    Auto,
    /// Always edit `/etc/resolv.conf`.
    File,
}

/// How the DNS settings were installed, so that they can be removed.
#[derive(Debug)]
enum Installed {
    /// A `resolvconf` record, by name.
    Resolvconf(String),
    /// systemd-resolved settings on an interface.
    Resolvectl(String),
    /// Lines we added to `resolv.conf`, and the `search` line we replaced.
    File {
        added: Vec<String>,
        replaced_search: Option<String>,
    },
}

/// The DNS settings of a tunnel, removed by [`Dns::remove`].
#[derive(Debug)]
pub struct Dns {
    installed: Installed,
}

impl Dns {
    /// Installs `servers` and the search `domains` for the tunnel
    /// `interface` with `tool`.
    pub async fn install(
        interface: &str,
        servers: &[Ipv4Addr],
        domains: &[String],
        tool: DnsTool,
    ) -> Result<Self> {
        let servers_text = servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let domains_text = domains.join(" ");
        let mut lines: Vec<String> = servers
            .iter()
            .map(|server| format!("nameserver {server}"))
            .collect();
        if !domains.is_empty() {
            lines.push(format!("search {domains_text}"));
        }
        if tool == DnsTool::Auto && tool_available("resolvconf") {
            let record = format!("{interface}.openfortivpn");
            let input = lines.join("\n") + "\n";
            run("resolvconf", &["-a", &record], Some(&input)).await?;
            tracing::info!(
                "Added nameservers [{servers_text}] and search domains [{domains_text}] through resolvconf ({record})."
            );
            return Ok(Self {
                installed: Installed::Resolvconf(record),
            });
        }
        if tool == DnsTool::Auto && resolved_manages(Path::new(RESOLV_CONF)) {
            if tool_available("resolvectl") {
                let mut dns = vec!["dns", interface];
                let servers: Vec<String> = servers.iter().map(ToString::to_string).collect();
                dns.extend(servers.iter().map(String::as_str));
                run("resolvectl", &dns, None).await?;
                if !domains.is_empty() {
                    let mut domain = vec!["domain", interface];
                    domain.extend(domains.iter().map(String::as_str));
                    run("resolvectl", &domain, None).await?;
                }
                tracing::info!(
                    "Added nameservers [{servers_text}] and search domains [{domains_text}] to systemd-resolved for {interface}."
                );
                return Ok(Self {
                    installed: Installed::Resolvectl(interface.to_owned()),
                });
            }
            tracing::warn!(
                "{RESOLV_CONF} is managed by systemd-resolved, which ignores direct edits; install resolvconf or resolvectl."
            );
        }
        let installed = edit_resolv_conf(Path::new(RESOLV_CONF), servers, domains)?;
        tracing::info!(
            "Added nameservers [{servers_text}] and search domains [{domains_text}] to {RESOLV_CONF}."
        );
        Ok(Self { installed })
    }

    /// Puts the resolver configuration back.
    pub async fn remove(&mut self) {
        let result = match &self.installed {
            Installed::Resolvconf(record) => {
                run("resolvconf", &["-d", record], None).await.map(drop)
            }
            Installed::Resolvectl(interface) => run("resolvectl", &["revert", interface], None)
                .await
                .map(drop),
            Installed::File {
                added,
                replaced_search,
            } => restore_resolv_conf(Path::new(RESOLV_CONF), added, replaced_search.as_deref()),
        };
        if let Err(error) = result {
            tracing::warn!("Could not restore the DNS configuration ({error}).");
        }
    }
}

/// Whether `program` is on the `PATH` (or in the usual sbin directories).
fn tool_available(program: &str) -> bool {
    let dirs = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    dirs.iter()
        .chain([PathBuf::from("/sbin"), PathBuf::from("/usr/sbin")].iter())
        .any(|dir| dir.join(program).is_file())
}

/// Whether `path` is one of the files systemd-resolved generates, which
/// it overwrites and does not read.
fn resolved_manages(path: &Path) -> bool {
    std::fs::canonicalize(path).is_ok_and(|target| target.starts_with(RESOLVED_DIR))
}

fn read_resolv_conf(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Resolver {
        path: path.display().to_string(),
        source,
    })?;
    Ok(text.lines().map(str::to_owned).collect())
}

fn write_resolv_conf(path: &Path, lines: &[String]) -> Result<()> {
    // Written in place so that a symbolic link (systemd-resolved) is
    // followed rather than replaced.
    let text = lines.join("\n") + "\n";
    std::fs::write(path, text).map_err(|source| Error::Resolver {
        path: path.display().to_string(),
        source,
    })
}

/// Prepends the nameservers that are not there yet and puts `domains`
/// first in the search list.
fn edit_resolv_conf(path: &Path, servers: &[Ipv4Addr], domains: &[String]) -> Result<Installed> {
    let mut lines = read_resolv_conf(path)?;
    let mut added = Vec::new();
    let mut replaced_search = None;

    if !domains.is_empty() {
        let existing = lines
            .iter()
            .position(|line| line.split_whitespace().next() == Some("search"));
        let ours = domains.join(" ");
        let new_line = if let Some(index) = existing {
            let old = lines.remove(index);
            let kept: Vec<&str> = old
                .split_whitespace()
                .skip(1)
                .filter(|existing| !domains.iter().any(|domain| domain == existing))
                .collect();
            let new_line = format!("search {ours} {}", kept.join(" "))
                .trim_end()
                .to_owned();
            replaced_search = Some(old);
            lines.insert(index, new_line.clone());
            new_line
        } else {
            let new_line = format!("search {ours}");
            lines.insert(0, new_line.clone());
            new_line
        };
        added.push(new_line);
    }
    for server in servers.iter().rev() {
        let line = format!("nameserver {server}");
        if lines.iter().any(|existing| existing.trim() == line) {
            tracing::debug!("{line} is already in {}", path.display());
            continue;
        }
        lines.insert(0, line.clone());
        added.push(line);
    }
    write_resolv_conf(path, &lines)?;
    tracing::debug!("updated {}", path.display());
    Ok(Installed::File {
        added,
        replaced_search,
    })
}

/// Removes the lines we added; the `search` line we replaced goes back in
/// place of ours.
fn restore_resolv_conf(path: &Path, added: &[String], replaced_search: Option<&str>) -> Result<()> {
    if added.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = read_resolv_conf(path)?
        .into_iter()
        .filter_map(|line| {
            if !added.contains(&line) {
                return Some(line);
            }
            replaced_search
                .filter(|_| line.starts_with("search"))
                .map(str::to_owned)
        })
        .collect();
    write_resolv_conf(path, &lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_resolv_conf(name: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ofv-net-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write");
        path
    }

    #[test]
    fn edits_and_restores_resolv_conf() {
        let original = "# generated\nnameserver 1.1.1.1\nsearch home.arpa\n";
        let path = temp_resolv_conf("edit.conf", original);
        let servers = [Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(1, 1, 1, 1)];
        let domains = ["corp.example".to_owned(), "home.arpa".to_owned()];
        let installed = edit_resolv_conf(&path, &servers, &domains).expect("edit");
        let edited = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            edited,
            "nameserver 10.0.0.53\n# generated\nnameserver 1.1.1.1\nsearch corp.example home.arpa\n"
        );
        let Installed::File {
            added,
            replaced_search,
        } = installed
        else {
            panic!("expected a file edit");
        };
        assert_eq!(replaced_search.as_deref(), Some("search home.arpa"));
        restore_resolv_conf(&path, &added, replaced_search.as_deref()).expect("restore");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), original);
    }

    #[test]
    fn adds_a_search_line_when_none_exists() {
        let path = temp_resolv_conf("search.conf", "nameserver 9.9.9.9\n");
        let installed = edit_resolv_conf(&path, &[], &["corp.example".to_owned()]).expect("edit");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "search corp.example\nnameserver 9.9.9.9\n"
        );
        let Installed::File { added, .. } = installed else {
            panic!("expected a file edit");
        };
        restore_resolv_conf(&path, &added, None).expect("restore");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "nameserver 9.9.9.9\n"
        );
    }
}
