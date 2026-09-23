use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::{Error, Result};

/// Runs a command, feeding it `stdin`, and returns its standard output.
pub(crate) async fn run(program: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
    let command = format!("{program} {}", args.join(" "));
    tracing::debug!("running: {command}");
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| Error::Spawn {
            command: command.clone(),
            source,
        })?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes())
            .await
            .map_err(|source| Error::Spawn {
                command: command.clone(),
                source,
            })?;
        drop(pipe);
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|source| Error::Spawn {
            command: command.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::Command {
            command,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Whether the failure of a command means the route already exists.
pub(crate) fn already_exists(error: &Error) -> bool {
    matches!(error, Error::Command { stderr, .. }
        if stderr.contains("File exists") || stderr.contains("already in table"))
}
