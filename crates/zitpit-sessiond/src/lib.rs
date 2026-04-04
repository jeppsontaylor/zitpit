use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::Command,
};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::Serialize;
use zitpit_core::{BehaviorDecision, BehaviorRequest, PolicyOutcome};

pub fn run_interactive_session(tmux_bin: &str, tmux_conf: &str, session_name: &str) -> Result<()> {
    let status = Command::new(tmux_bin)
        .args(["-f", tmux_conf, "new-session", "-A", "-s", session_name])
        .status()
        .with_context(|| format!("launch tmux session via {tmux_bin}"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("tmux exited with status {status}");
    }
}

pub fn run_managed_command(request: &BehaviorRequest, decision: &BehaviorDecision) -> Result<i32> {
    match decision.outcome {
        PolicyOutcome::Allow => {
            let command = request
                .command
                .as_ref()
                .context("missing canonical command for allowed request")?;
            if command.parse_error.is_some() {
                bail!("protected mode cannot execute a command with shell metacharacters");
            }
            let binary = &command.binary_path;
            let args = command.argv.iter().skip(1).cloned().collect::<Vec<_>>();
            let mut process = Command::new(binary);
            process.args(args).current_dir(&command.cwd);
            for (name, value) in &command.env {
                process.env(name, value);
            }
            let status = process
                .status()
                .with_context(|| format!("run allowed command: {}", command.argv.join(" ")))?;
            if status.success() {
                Ok(0)
            } else {
                Ok(status.code().unwrap_or(1))
            }
        }
        PolicyOutcome::Deny | PolicyOutcome::BrokerOnly | PolicyOutcome::Unsupported => {
            eprintln!("ZitPit blocked this command.");
            eprintln!("{}", decision.reason);
            Ok(126)
        }
        PolicyOutcome::StepUp | PolicyOutcome::Quarantine => {
            eprintln!("ZitPit held this command for a stronger policy path.");
            eprintln!("{}", decision.reason);
            Ok(126)
        }
    }
}

pub fn append_audit_record(
    path: &Path,
    raw: &str,
    request: &BehaviorRequest,
    decision: &BehaviorDecision,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open audit log {}", path.display()))?;
    let record = AuditRecord {
        at: Utc::now(),
        raw_command: redact_command(raw),
        request: request.clone(),
        decision: decision.clone(),
    };
    writeln!(file, "{}", serde_json::to_string(&record)?)?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct AuditRecord {
    at: chrono::DateTime<Utc>,
    raw_command: String,
    request: BehaviorRequest,
    decision: BehaviorDecision,
}

fn redact_command(raw: &str) -> String {
    let mut redacted = raw.to_string();
    for marker in [
        "Authorization:",
        "authorization:",
        "Bearer ",
        "AWS_SECRET_ACCESS_KEY=",
    ] {
        if let Some(index) = redacted.find(marker) {
            redacted.truncate(index + marker.len());
            redacted.push_str("[REDACTED]");
            break;
        }
    }
    redacted
}
