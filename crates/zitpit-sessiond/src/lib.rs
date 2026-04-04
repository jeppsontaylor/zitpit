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

pub fn run_managed_command(raw: &str, decision: &BehaviorDecision) -> Result<()> {
    match decision.outcome {
        PolicyOutcome::Allow => {
            let status = Command::new("/bin/zsh")
                .args(["-lc", raw])
                .status()
                .with_context(|| format!("run allowed command: {raw}"))?;
            if status.success() {
                Ok(())
            } else {
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        PolicyOutcome::Deny | PolicyOutcome::BrokerOnly | PolicyOutcome::Unsupported => {
            eprintln!("ZitPit blocked this command.");
            eprintln!("{}", decision.reason);
            std::process::exit(126);
        }
        PolicyOutcome::StepUp | PolicyOutcome::Quarantine => {
            eprintln!("ZitPit held this command for a stronger policy path.");
            eprintln!("{}", decision.reason);
            std::process::exit(126);
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
        raw_command: raw.to_string(),
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
