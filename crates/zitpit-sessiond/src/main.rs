use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use zitpit_core::behavior::{SessionContext, SessionPolicy, canonicalize_command};
use zitpit_sessiond::{append_audit_record, run_interactive_session, run_managed_command};

#[derive(Debug, Parser)]
#[command(name = "zitpit-sessiond")]
struct Cli {
    #[arg(long)]
    command: Option<String>,
    #[arg(long, default_value = "/bin/tmux")]
    tmux_bin: String,
    #[arg(long, default_value = "/etc/zitpit/tmux-protected.conf")]
    tmux_conf: String,
    #[arg(long, default_value = "zitpit-protected")]
    session_name: String,
    #[arg(long, default_value = "/home/z/workspace/.zitpit/session-audit.jsonl")]
    audit_log: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = SessionContext::from_env();
    let policy = SessionPolicy::default();

    if let Some(raw) = cli
        .command
        .or_else(|| std::env::var("SSH_ORIGINAL_COMMAND").ok())
    {
        let managed = canonicalize_command(&ctx, &raw);
        let decision = policy.decide(&managed.request);
        append_audit_record(&cli.audit_log, &raw, &managed.request, &decision)
            .with_context(|| format!("append audit record to {}", cli.audit_log.display()))?;
        return run_managed_command(&raw, &decision);
    }

    if std::env::var_os("SSH_ORIGINAL_COMMAND").is_some() {
        bail!("empty SSH_ORIGINAL_COMMAND is not allowed");
    }

    run_interactive_session(&cli.tmux_bin, &cli.tmux_conf, &cli.session_name)
}
