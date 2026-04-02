use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
mod bench;
use zitpit_admin_client::AdminClient;
use zitpit_battle_runner::{BattleRunner, BrowserMode};
use zitpit_battle_types::BattleSuite;
use zitpit_config::RuntimePaths;
use zitpit_core::CapturedRequest;
use zitpit_core::manifest::digest_for;

const DEMO_PROXY_ADMIN_BASE: &str = "http://127.0.0.1:43000";
const DEMO_MANIFEST_BASE: &str = "http://127.0.0.1:43001";
const DEMO_LAB_BASE: &str = "http://127.0.0.1:43002";
const DEMO_WATCH_BASE: &str = "http://127.0.0.1:43003";
const DEMO_NODE_BASE: &str = "http://127.0.0.1:43006";
const DEMO_PROXY_HEALTH: &str = "http://127.0.0.1:43000/healthz";
const DEMO_MANIFEST_HEALTH: &str = "http://127.0.0.1:43001/healthz";
const DEMO_LAB_HEALTH: &str = "http://127.0.0.1:43002/healthz";
const DEMO_WATCH_HEALTH: &str = "http://127.0.0.1:43003/healthz";
const DEMO_NODE_HEALTH: &str = "http://127.0.0.1:43006/healthz";
const DEMO_SSH_PORT: &str = "42222";
const DEMO_SSH_ALIAS: &str = "zitpit";
const DEMO_SSH_HOST_KEY_ALIAS: &str = "zitpit-local";

#[derive(Debug, Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Debug, Subcommand)]
enum TopLevelCommand {
    Bench {
        #[command(subcommand)]
        command: BenchCommand,
    },
    Battle {
        #[command(subcommand)]
        command: BattleCommand,
    },
    Demo {
        #[command(subcommand)]
        command: DemoCommand,
    },
}

#[derive(Debug, Subcommand)]
enum BattleCommand {
    Lint,
    Fast,
    GitCore,
    Actions,
    Artifact,
    Browser,
    Queue,
    Controls,
    PublicCore,
    All,
    Vm,
}

#[derive(Debug, Subcommand)]
enum DemoCommand {
    Setup {
        #[arg(long, value_name = "PATH")]
        ssh_key: Option<PathBuf>,
    },
    Up,
    Down,
    Status,
    Logs,
    SshConfig,
    Smoke,
    BuildTimings,
}

#[derive(Debug, Subcommand)]
enum BenchCommand {
    Run {
        #[arg(long = "repo")]
        repos: Vec<String>,
        #[arg(long, default_value_t = 1)]
        samples: usize,
        #[arg(long)]
        json_out: Option<PathBuf>,
        #[arg(long)]
        md_out: Option<PathBuf>,
    },
}

struct DemoPaths {
    root: PathBuf,
    runtime: RuntimePaths,
    ssh_dir: PathBuf,
    env_file: PathBuf,
    approved_source: String,
    unknown_source: String,
    real_public_source: String,
}

impl DemoPaths {
    fn load() -> Self {
        let root = PathBuf::from(".zitpit/demo");
        let runtime = RuntimePaths::new(root.join("state"));
        Self {
            ssh_dir: root.join("ssh"),
            env_file: root.join("demo.env"),
            approved_source: "http://github.com/jeppsontaylor/approved.git".to_string(),
            unknown_source: "http://github.com/jeppsontaylor/unknown.git".to_string(),
            real_public_source: "http://github.com/axios/axios.git".to_string(),
            root,
            runtime,
        }
    }

    fn generated_client_private_key(&self) -> PathBuf {
        self.ssh_dir.join("zitpit_client_ed25519")
    }

    fn generated_client_public_key(&self) -> PathBuf {
        self.ssh_dir.join("zitpit_client_ed25519.pub")
    }

    fn staged_public_key(&self) -> PathBuf {
        self.ssh_dir.join("authorized_key.pub")
    }

    fn server_host_key(&self) -> PathBuf {
        self.ssh_dir.join("ssh_host_ed25519_key")
    }

    fn server_host_public_key(&self) -> PathBuf {
        self.ssh_dir.join("ssh_host_ed25519_key.pub")
    }

    fn setup_metadata(&self) -> PathBuf {
        self.root.join("setup.json")
    }

    fn smoke_known_hosts(&self) -> PathBuf {
        self.ssh_dir.join("known_hosts")
    }

    fn upstream_repo_root(&self, source: &str) -> PathBuf {
        let parsed = Url::parse(source).expect("valid demo source url");
        self.runtime
            .git_upstream_root
            .join(parsed.path().trim_start_matches('/'))
    }

    fn approved_upstream_repo_root(&self) -> PathBuf {
        self.upstream_repo_root(&self.approved_source)
    }

    fn unknown_upstream_repo_root(&self) -> PathBuf {
        self.upstream_repo_root(&self.unknown_source)
    }

    fn last_up_report(&self) -> PathBuf {
        self.root.join("last_up.json")
    }

    fn last_smoke_report(&self) -> PathBuf {
        self.root.join("last_smoke.json")
    }

    fn last_build_report(&self) -> PathBuf {
        self.root.join("last_build_timings.json")
    }
}

#[derive(Debug, Serialize)]
struct UpSummary {
    compose_build_ms: u128,
    health_wait_ms: u128,
    seed_ms: u128,
    ssh_port: &'static str,
    proxy_admin_base: &'static str,
}

#[derive(Debug, Serialize)]
struct CommandSummary {
    command: String,
    exit_code: Option<i32>,
    elapsed_ms: u128,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct SmokeSummary {
    interactive_protected: CommandSummary,
    interactive_fail_closed: CommandSummary,
    approved_first: CommandSummary,
    approved_cached: CommandSummary,
    unknown_pending: CommandSummary,
    real_public_pending: CommandSummary,
    bypass_attempt: CommandSummary,
    approved_first_request_id: String,
    approved_cached_request_id: String,
    unknown_request_id: String,
    real_public_request_id: String,
    approved_first_proxy_ms: i64,
    approved_cached_proxy_ms: i64,
    unknown_proxy_ms: i64,
    real_public_proxy_ms: i64,
}

#[derive(Debug, Serialize)]
struct BuildTimingSummary {
    first_build_ms: u128,
    warm_build_ms: u128,
    no_op_build_ms: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DemoSetupMetadata {
    client_private_key: PathBuf,
    staged_public_key: PathBuf,
    server_host_key: PathBuf,
    server_host_public_key: PathBuf,
    generated_client_key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DemoClientIdentity {
    private_key: PathBuf,
    public_key: PathBuf,
    generated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostPlatform {
    MacOs,
    Ubuntu,
    Linux,
    Other,
}

impl HostPlatform {
    fn detect() -> Self {
        match std::env::consts::OS {
            "macos" => Self::MacOs,
            "linux" => {
                let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
                if os_release.contains("ID=ubuntu")
                    || os_release.contains("ID_LIKE=ubuntu")
                    || os_release.contains("ID_LIKE=\"ubuntu\"")
                {
                    Self::Ubuntu
                } else {
                    Self::Linux
                }
            }
            _ => Self::Other,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::MacOs => "macOS",
            Self::Ubuntu => "Ubuntu",
            Self::Linux => "Linux",
            Self::Other => "unsupported host OS",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        TopLevelCommand::Bench { command } => match command {
            BenchCommand::Run {
                repos,
                samples,
                json_out,
                md_out,
            } => {
                bench::run(bench::BenchRunConfig {
                    repos,
                    samples,
                    json_out,
                    md_out,
                })
                .await
            }
        },
        TopLevelCommand::Battle { command } => match command {
            BattleCommand::Lint => battle_lint(),
            BattleCommand::Fast => {
                battle_run(BattleSuite::Fast, BrowserMode::SkipIfUnavailable).await
            }
            BattleCommand::GitCore => {
                battle_run(BattleSuite::GitCore, BrowserMode::SkipIfUnavailable).await
            }
            BattleCommand::Actions => {
                battle_run(BattleSuite::Actions, BrowserMode::SkipIfUnavailable).await
            }
            BattleCommand::Artifact => {
                battle_run(BattleSuite::Artifact, BrowserMode::SkipIfUnavailable).await
            }
            BattleCommand::Browser => battle_run(BattleSuite::Browser, BrowserMode::Require).await,
            BattleCommand::Queue => {
                battle_run(BattleSuite::Queue, BrowserMode::SkipIfUnavailable).await
            }
            BattleCommand::Controls => {
                battle_run(BattleSuite::Controls, BrowserMode::SkipIfUnavailable).await
            }
            BattleCommand::PublicCore => {
                battle_run(BattleSuite::PublicCore, BrowserMode::SkipIfUnavailable).await
            }
            BattleCommand::All => battle_all().await,
            BattleCommand::Vm => battle_run(BattleSuite::Vm, BrowserMode::SkipIfUnavailable).await,
        },
        TopLevelCommand::Demo { command } => match command {
            DemoCommand::Setup { ssh_key } => demo_setup(ssh_key).await,
            DemoCommand::Up => demo_up().await,
            DemoCommand::Down => demo_down(),
            DemoCommand::Status => demo_status().await,
            DemoCommand::Logs => demo_logs(),
            DemoCommand::SshConfig => demo_ssh_config(),
            DemoCommand::Smoke => demo_smoke().await,
            DemoCommand::BuildTimings => demo_build_timings().await,
        },
    }
}

fn battle_lint() -> Result<()> {
    let runner = BattleRunner::default();
    let packs = runner.lint()?;
    println!("validated {} battle packs", packs.len());
    for pack in packs {
        println!("  - {}", pack.pack.pack_id);
    }
    Ok(())
}

async fn battle_run(suite: BattleSuite, browser_mode: BrowserMode) -> Result<()> {
    let runner = BattleRunner::default();
    let report = runner.run_suite(suite, browser_mode).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.failed > 0 {
        bail!(
            "battle suite {:?} had {} failing packs",
            suite,
            report.failed
        );
    }
    Ok(())
}

async fn battle_all() -> Result<()> {
    for suite in [
        BattleSuite::Fast,
        BattleSuite::GitCore,
        BattleSuite::Actions,
        BattleSuite::Artifact,
        BattleSuite::Browser,
        BattleSuite::Queue,
        BattleSuite::Controls,
        BattleSuite::PublicCore,
    ] {
        battle_run(suite, BrowserMode::SkipIfUnavailable).await?;
    }
    Ok(())
}

async fn demo_setup(ssh_key: Option<PathBuf>) -> Result<()> {
    let paths = DemoPaths::load();
    let platform = HostPlatform::detect();
    println!("Detected host platform: {}.", platform.label());
    run_preflight_checks(platform)?;
    let metadata = prepare_demo_launch(&paths, ssh_key.as_deref())?;
    start_demo_stack(&paths).await?;
    print_setup_completion(&metadata)?;
    Ok(())
}

async fn demo_up() -> Result<()> {
    let paths = DemoPaths::load();
    let metadata = prepare_demo_launch(&paths, None)?;
    start_demo_stack(&paths).await?;
    print_setup_completion(&metadata)?;
    Ok(())
}

fn prepare_demo_launch(
    paths: &DemoPaths,
    ssh_key_override: Option<&Path>,
) -> Result<DemoSetupMetadata> {
    fs::create_dir_all(&paths.root)?;
    fs::create_dir_all(&paths.ssh_dir)?;
    let metadata = ensure_demo_setup_metadata(paths, ssh_key_override)?;
    reset_demo_state(paths)?;
    paths.runtime.ensure_dirs()?;
    seed_approved_repo(paths)?;
    write_env_file(paths, &metadata)?;
    Ok(metadata)
}

async fn start_demo_stack(paths: &DemoPaths) -> Result<()> {
    let build_start = Instant::now();
    let no_build = std::env::var("ZITPIT_DEMO_NO_BUILD")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut compose_up = docker_command();
    compose_up
        .args(["compose", "--env-file"])
        .arg(&paths.env_file)
        .args(["-f", "compose.yaml", "up", "--force-recreate", "-d"]);
    if !no_build {
        compose_up.arg("--build");
    }
    run_command(&mut compose_up)?;
    let compose_build_ms = build_start.elapsed().as_millis();

    let health_start = Instant::now();
    wait_for(DEMO_PROXY_HEALTH).await?;
    wait_for(DEMO_MANIFEST_HEALTH).await?;
    wait_for(DEMO_LAB_HEALTH).await?;
    wait_for(DEMO_WATCH_HEALTH).await?;
    wait_for(DEMO_NODE_HEALTH).await?;
    let health_wait_ms = health_start.elapsed().as_millis();

    let seed_start = Instant::now();
    seed_manifest_and_node(paths).await?;
    let seed_ms = seed_start.elapsed().as_millis();
    write_json_report(
        &paths.last_up_report(),
        &UpSummary {
            compose_build_ms,
            health_wait_ms,
            seed_ms,
            ssh_port: DEMO_SSH_PORT,
            proxy_admin_base: DEMO_PROXY_ADMIN_BASE,
        },
    )?;
    println!("ZitPit demo stack is up.");
    Ok(())
}

fn ensure_demo_setup_metadata(
    paths: &DemoPaths,
    ssh_key_override: Option<&Path>,
) -> Result<DemoSetupMetadata> {
    let identity = select_client_identity(paths, ssh_key_override, None)?;
    fs::copy(&identity.public_key, paths.staged_public_key()).with_context(|| {
        format!(
            "copy SSH public key {} to {}",
            identity.public_key.display(),
            paths.staged_public_key().display()
        )
    })?;
    ensure_server_host_keypair(paths)?;

    let metadata = DemoSetupMetadata {
        client_private_key: identity.private_key.canonicalize().with_context(|| {
            format!("resolve SSH private key {}", identity.private_key.display())
        })?,
        staged_public_key: paths.staged_public_key().canonicalize().with_context(|| {
            format!(
                "resolve staged SSH public key {}",
                paths.staged_public_key().display()
            )
        })?,
        server_host_key: paths.server_host_key().canonicalize().with_context(|| {
            format!("resolve SSH host key {}", paths.server_host_key().display())
        })?,
        server_host_public_key: paths.server_host_public_key().canonicalize().with_context(
            || {
                format!(
                    "resolve SSH host public key {}",
                    paths.server_host_public_key().display()
                )
            },
        )?,
        generated_client_key: identity.generated,
    };
    write_json_report(&paths.setup_metadata(), &metadata)?;
    Ok(metadata)
}

fn load_setup_metadata(paths: &DemoPaths) -> Result<DemoSetupMetadata> {
    let raw = fs::read_to_string(paths.setup_metadata()).with_context(|| {
        format!(
            "read demo setup metadata {}; run `cargo run -p xtask -- demo setup` first",
            paths.setup_metadata().display()
        )
    })?;
    serde_json::from_str(&raw).with_context(|| {
        format!(
            "parse demo setup metadata {}",
            paths.setup_metadata().display()
        )
    })
}

fn select_client_identity(
    paths: &DemoPaths,
    ssh_key_override: Option<&Path>,
    home_override: Option<&Path>,
) -> Result<DemoClientIdentity> {
    if let Some(private_key) = ssh_key_override {
        return explicit_client_identity(private_key);
    }

    if let Some(identity) = discover_existing_client_identity(home_override)? {
        return Ok(identity);
    }

    ensure_generated_client_keypair(paths)?;
    Ok(DemoClientIdentity {
        private_key: paths.generated_client_private_key(),
        public_key: paths.generated_client_public_key(),
        generated: true,
    })
}

fn explicit_client_identity(private_key: &Path) -> Result<DemoClientIdentity> {
    let private_key = private_key.canonicalize().with_context(|| {
        format!(
            "resolve requested SSH private key {}",
            private_key.display()
        )
    })?;
    let public_key = PathBuf::from(format!("{}.pub", private_key.display()));
    if !public_key.exists() {
        bail!(
            "requested SSH key {} is missing its matching public key {}",
            private_key.display(),
            public_key.display()
        );
    }
    Ok(DemoClientIdentity {
        private_key,
        public_key,
        generated: false,
    })
}

fn discover_existing_client_identity(
    home_override: Option<&Path>,
) -> Result<Option<DemoClientIdentity>> {
    let Some(home_dir) = home_override
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
    else {
        return Ok(None);
    };

    for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
        let private_key = home_dir.join(".ssh").join(name);
        let public_key = home_dir.join(".ssh").join(format!("{name}.pub"));
        if private_key.exists() && public_key.exists() {
            return Ok(Some(DemoClientIdentity {
                private_key,
                public_key,
                generated: false,
            }));
        }
    }
    Ok(None)
}

fn ensure_generated_client_keypair(paths: &DemoPaths) -> Result<()> {
    if paths.generated_client_private_key().exists() && paths.generated_client_public_key().exists()
    {
        return Ok(());
    }
    run_command(
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f"])
            .arg(paths.generated_client_private_key()),
    )
}

fn ensure_server_host_keypair(paths: &DemoPaths) -> Result<()> {
    if paths.server_host_key().exists() && paths.server_host_public_key().exists() {
        return Ok(());
    }
    run_command(
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f"])
            .arg(paths.server_host_key()),
    )
}

fn run_preflight_checks(platform: HostPlatform) -> Result<()> {
    if platform == HostPlatform::Other {
        bail!("ZitPit demo setup currently supports macOS and Linux hosts.");
    }

    let mut issues = Vec::new();
    for binary in ["cargo", "git", "ssh", "ssh-keygen"] {
        if !shell_command_succeeds(&format!("command -v {binary} >/dev/null 2>&1")) {
            issues.push(format!(
                "missing `{binary}`: {}",
                install_hint(platform, binary)
            ));
        }
    }

    let docker_path = resolve_docker_binary();
    let docker_available = (docker_path == Path::new("docker")
        && shell_command_succeeds("command -v docker >/dev/null 2>&1"))
        || docker_path.exists();
    if !docker_available {
        issues.push(format!(
            "missing `docker`: {}",
            install_hint(platform, "docker")
        ));
    } else {
        if !command_succeeds(docker_command().args(["compose", "version"])) {
            issues.push(format!(
                "`docker compose` is unavailable: {}",
                install_hint(platform, "docker-compose")
            ));
        }
        if !command_succeeds(docker_command().arg("info")) {
            issues.push(format!(
                "Docker daemon is unavailable: {}",
                docker_daemon_hint(platform)
            ));
        }
    }

    for port in [42222, 43000, 43001, 43002, 43003, 43004, 43006, 5432] {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            issues.push(format!(
                "local port {port} is already in use; stop the conflicting service or adjust the demo port mapping before running setup"
            ));
        }
    }

    if issues.is_empty() {
        println!("Preflight checks passed.");
        Ok(())
    } else {
        bail!("Preflight checks failed:\n- {}", issues.join("\n- "))
    }
}

fn install_hint(platform: HostPlatform, binary: &str) -> &'static str {
    match (platform, binary) {
        (HostPlatform::MacOs, "docker") | (HostPlatform::MacOs, "docker-compose") => {
            "install Docker Desktop for macOS and reopen your shell"
        }
        (HostPlatform::MacOs, _) => {
            "install Xcode Command Line Tools (`xcode-select --install`) and Rust via https://rustup.rs/"
        }
        (HostPlatform::Ubuntu, "cargo") => {
            "install Rust with `curl https://sh.rustup.rs -sSf | sh` and restart your shell"
        }
        (HostPlatform::Ubuntu, "docker") | (HostPlatform::Ubuntu, "docker-compose") => {
            "install Docker Engine plus the Compose plugin, for example `sudo apt install docker.io docker-compose-plugin`"
        }
        (HostPlatform::Ubuntu, _) => {
            "install the missing package, for example `sudo apt install git openssh-client`"
        }
        (HostPlatform::Linux, "cargo") => {
            "install Rust with https://rustup.rs/ and restart your shell"
        }
        (HostPlatform::Linux, "docker") | (HostPlatform::Linux, "docker-compose") => {
            "install Docker Engine and the Compose plugin for your distro"
        }
        (HostPlatform::Linux, _) => "install the missing binary from your distro package manager",
        _ => "install the required dependency and retry setup",
    }
}

fn docker_daemon_hint(platform: HostPlatform) -> &'static str {
    match platform {
        HostPlatform::MacOs => "start Docker Desktop and wait for it to finish booting",
        HostPlatform::Ubuntu => {
            "start Docker and ensure your user can access it, for example `sudo systemctl start docker` and add yourself to the `docker` group if needed"
        }
        HostPlatform::Linux => "start Docker and ensure your user can access the daemon socket",
        HostPlatform::Other => "start Docker and ensure the daemon is reachable",
    }
}

fn command_succeeds(command: &mut Command) -> bool {
    command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn shell_command_succeeds(command: &str) -> bool {
    Command::new("sh")
        .args(["-lc", command])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn demo_down() -> Result<()> {
    let paths = DemoPaths::load();
    if !paths.env_file.exists() {
        return Ok(());
    }
    cleanup_demo_runtime_contents(&paths)?;
    run_command(
        docker_command()
            .args(["compose", "--env-file"])
            .arg(&paths.env_file)
            .args([
                "-f",
                "compose.yaml",
                "down",
                "--remove-orphans",
                "--volumes",
            ]),
    )?;
    reset_demo_state(&paths)
}

async fn demo_status() -> Result<()> {
    let client = Client::new();
    for (name, url) in [
        ("proxy", DEMO_PROXY_HEALTH),
        ("manifest", DEMO_MANIFEST_HEALTH),
        ("lab", DEMO_LAB_HEALTH),
        ("watch", DEMO_WATCH_HEALTH),
        ("node-agent", DEMO_NODE_HEALTH),
    ] {
        let status = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("request {name}"))?
            .status();
        println!("{name:<12} {status}");
    }
    Ok(())
}

fn demo_logs() -> Result<()> {
    let paths = DemoPaths::load();
    run_command(
        docker_command()
            .args(["compose", "--env-file"])
            .arg(&paths.env_file)
            .args(["-f", "compose.yaml", "logs", "--tail", "200", "-f"]),
    )
}

fn demo_ssh_config() -> Result<()> {
    let paths = DemoPaths::load();
    let metadata = load_setup_metadata(&paths)?;
    print_ssh_config(&metadata);
    Ok(())
}

async fn demo_smoke() -> Result<()> {
    let paths = DemoPaths::load();
    let metadata = load_setup_metadata(&paths)?;
    let client = Client::new();
    for url in [
        DEMO_PROXY_HEALTH,
        DEMO_MANIFEST_HEALTH,
        DEMO_LAB_HEALTH,
        DEMO_WATCH_HEALTH,
        DEMO_NODE_HEALTH,
    ] {
        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            bail!("health check failed for {url}");
        }
    }

    let ssh_base = demo_ssh_base(&metadata, &paths.smoke_known_hosts())?;

    let interactive_protected = run_ssh_interactive_timed(&ssh_base, "exit\n")?;
    let interactive_output = format!(
        "{}{}",
        String::from_utf8_lossy(&interactive_protected.output.stdout),
        String::from_utf8_lossy(&interactive_protected.output.stderr)
    );
    if !interactive_output.contains("ZITPIT PROTECTED") {
        bail!("interactive login did not render the protected tmux badge");
    }
    if !interactive_output.contains("\u{1b}]11;#103a1f") {
        bail!("interactive login did not emit the background color OSC 11 sequence");
    }
    if !interactive_output.contains("\u{1b}]2;ZitPit Protected SSH") {
        bail!("interactive login did not emit the window title OSC 2 sequence");
    }

    let admin = AdminClient::new(
        DEMO_PROXY_ADMIN_BASE,
        DEMO_MANIFEST_BASE,
        DEMO_LAB_BASE,
        DEMO_WATCH_BASE,
        DEMO_NODE_BASE,
    );

    clear_approved_demo_cache(&paths)?;

    run_command(Command::new("ssh").args(&ssh_base).arg("pwd"))?;
    let git_config = run_capture(Command::new("ssh").args(&ssh_base).arg("git config --list"))?;
    if !git_config.contains("http.proxy=http://zitpit-gateway:3004") {
        bail!("workspace git config did not include ZitPit proxy");
    }

    let approved_probe = git_smart_http_probe_command(&paths.approved_source);
    let unknown_probe = git_smart_http_probe_command(&paths.unknown_source);
    let real_public_probe = git_smart_http_probe_command(&paths.real_public_source);

    let approved_first = run_ssh_timed(&ssh_base, &approved_probe)?;
    if !approved_first.output.status.success() {
        bail!(
            "approved repo first fetch failed: {}{}",
            String::from_utf8_lossy(&approved_first.output.stdout),
            String::from_utf8_lossy(&approved_first.output.stderr)
        );
    }
    let approved_first_output = format!(
        "{}{}",
        String::from_utf8_lossy(&approved_first.output.stdout),
        String::from_utf8_lossy(&approved_first.output.stderr)
    );
    if !approved_first_output.contains("ZITPIT_HTTP_STATUS:200") {
        bail!("approved repo first fetch did not return HTTP 200: {approved_first_output}");
    }
    if !approved_first_output.contains("git-upload-pack") {
        bail!("approved repo first fetch did not return Git smart-HTTP service data");
    }
    let approved_first_lifecycle =
        find_git_lifecycle_since(&admin, &paths.approved_source, approved_first.started_at).await?;
    if !approved_first_lifecycle
        .trace
        .events
        .iter()
        .any(|event| event.kind == zitpit_core::ProxyTraceKind::FetchStarted)
    {
        bail!("approved repo first fetch did not perform an upstream acquisition");
    }

    let approved_cached = run_ssh_timed(&ssh_base, &approved_probe)?;
    if !approved_cached.output.status.success() {
        bail!(
            "approved repo cache-hit fetch failed: {}{}",
            String::from_utf8_lossy(&approved_cached.output.stdout),
            String::from_utf8_lossy(&approved_cached.output.stderr)
        );
    }
    let approved_cached_output = format!(
        "{}{}",
        String::from_utf8_lossy(&approved_cached.output.stdout),
        String::from_utf8_lossy(&approved_cached.output.stderr)
    );
    if !approved_cached_output.contains("ZITPIT_HTTP_STATUS:200") {
        bail!("approved repo cache-hit fetch did not return HTTP 200: {approved_cached_output}");
    }
    let approved_cached_lifecycle =
        find_git_lifecycle_since(&admin, &paths.approved_source, approved_cached.started_at)
            .await?;
    if !approved_cached_lifecycle
        .trace
        .events
        .iter()
        .any(|event| event.kind == zitpit_core::ProxyTraceKind::CacheHit)
    {
        bail!("approved repo second fetch did not hit the approved cache");
    }

    let unknown_result = run_ssh_timed(&ssh_base, &unknown_probe)?;
    let unknown_output = format!(
        "{}{}",
        String::from_utf8_lossy(&unknown_result.output.stdout),
        String::from_utf8_lossy(&unknown_result.output.stderr)
    );
    if !unknown_output.contains("ZITPIT_HTTP_STATUS:503") {
        bail!("unknown repo response did not return HTTP 503: {unknown_output}");
    }
    if !unknown_output.contains("check back in about") {
        bail!("unknown repo response did not include retry guidance: {unknown_output}");
    }
    let unknown_lifecycle =
        find_git_lifecycle_since(&admin, &paths.unknown_source, unknown_result.started_at).await?;

    let real_public_result = run_ssh_timed(&ssh_base, &real_public_probe)?;
    let real_public_output = format!(
        "{}{}",
        String::from_utf8_lossy(&real_public_result.output.stdout),
        String::from_utf8_lossy(&real_public_result.output.stderr)
    );
    if !real_public_output.contains("ZITPIT_HTTP_STATUS:503") {
        bail!("real public repo response did not return HTTP 503: {real_public_output}");
    }
    if !real_public_output.contains("check back in about") {
        bail!("real public repo response did not include retry guidance: {real_public_output}");
    }
    let real_public_lifecycle = find_git_lifecycle_since(
        &admin,
        &paths.real_public_source,
        real_public_result.started_at,
    )
    .await?;
    if !real_public_lifecycle
        .trace
        .events
        .iter()
        .any(|event| event.detail.contains("no seeded mirror found"))
    {
        bail!("real public repo did not report the live-fetch path in lifecycle events");
    }
    if real_public_lifecycle.trace.events.iter().any(|event| {
        event
            .detail
            .contains("does not appear to be a git repository")
    }) {
        bail!("real public repo regressed to the missing local mirror failure path");
    }

    let snapshot = admin.snapshot().await?;
    if !snapshot
        .quarantine_jobs
        .iter()
        .any(|job| job.artifact_key.source == paths.unknown_source)
    {
        bail!("quarantine jobs did not include unknown repo");
    }
    if !snapshot
        .lab_runs
        .iter()
        .any(|run| run.artifact_key.source == paths.unknown_source)
    {
        bail!("lab runs did not include unknown repo");
    }
    if !snapshot
        .evidence
        .iter()
        .any(|bundle| bundle.artifact_key.source == paths.unknown_source)
    {
        bail!("evidence did not include unknown repo");
    }
    if !snapshot
        .feed
        .iter()
        .any(|record| record.artifact.source == paths.unknown_source)
    {
        bail!("feed did not include unknown repo");
    }
    if !snapshot
        .quarantine_jobs
        .iter()
        .any(|job| job.artifact_key.source == paths.real_public_source)
    {
        bail!("quarantine jobs did not include real public repo");
    }
    if !snapshot
        .lab_runs
        .iter()
        .any(|run| run.artifact_key.source == paths.real_public_source)
    {
        bail!("lab runs did not include real public repo");
    }
    if !snapshot
        .evidence
        .iter()
        .any(|bundle| bundle.artifact_key.source == paths.real_public_source)
    {
        bail!("evidence did not include real public repo");
    }
    if !snapshot
        .feed
        .iter()
        .any(|record| record.artifact.source == paths.real_public_source)
    {
        bail!("feed did not include real public repo");
    }

    let bypass = Command::new("ssh")
        .args(&ssh_base)
        .arg("curl --noproxy '*' --connect-timeout 2 -I https://github.com")
        .output()
        .context("run workspace network isolation check")?;
    if bypass.status.success() {
        bail!("workspace unexpectedly reached github.com without the proxy path");
    }

    workspace_service_command(
        &paths,
        "mv /etc/zitpit/tmux-protected.conf /etc/zitpit/tmux-protected.conf.off",
    )?;
    let interactive_fail_closed = run_ssh_interactive_timed(&ssh_base, "exit\n");
    let restore_result = workspace_service_command(
        &paths,
        "mv /etc/zitpit/tmux-protected.conf.off /etc/zitpit/tmux-protected.conf",
    );
    let interactive_fail_closed = interactive_fail_closed?;
    restore_result?;
    if interactive_fail_closed.output.status.success() {
        bail!("interactive login unexpectedly succeeded after removing the tmux config");
    }
    let fail_closed_output = format!(
        "{}{}",
        String::from_utf8_lossy(&interactive_fail_closed.output.stdout),
        String::from_utf8_lossy(&interactive_fail_closed.output.stderr)
    );
    if !fail_closed_output.contains("ZitPit could not verify this SSH terminal as protected.") {
        bail!("interactive login did not fail closed with the expected safety message");
    }

    println!(
        "{}",
        format_git_lifecycle_report("approved-first-fetch", &approved_first_lifecycle)
    );
    println!(
        "{}",
        format_git_lifecycle_report("approved-cache-hit", &approved_cached_lifecycle)
    );
    println!(
        "{}",
        format_git_lifecycle_report("unknown-pending", &unknown_lifecycle)
    );
    println!(
        "{}",
        format_git_lifecycle_report("real-public-pending", &real_public_lifecycle)
    );
    println!(
        "{}",
        format_latency_comparison(
            &approved_first_lifecycle,
            approved_first.elapsed_ms,
            &approved_cached_lifecycle,
            approved_cached.elapsed_ms,
            &unknown_lifecycle,
            unknown_result.elapsed_ms,
        )
    );
    write_json_report(
        &paths.last_smoke_report(),
        &SmokeSummary {
            interactive_protected: CommandSummary::from_timed_command(
                "interactive protected login",
                &interactive_protected,
            ),
            interactive_fail_closed: CommandSummary::from_timed_command(
                "interactive fail-closed login",
                &interactive_fail_closed,
            ),
            approved_first: CommandSummary::from_timed_command(&approved_probe, &approved_first),
            approved_cached: CommandSummary::from_timed_command(&approved_probe, &approved_cached),
            unknown_pending: CommandSummary::from_timed_command(&unknown_probe, &unknown_result),
            real_public_pending: CommandSummary::from_timed_command(
                &real_public_probe,
                &real_public_result,
            ),
            bypass_attempt: CommandSummary::from_output(
                "curl --noproxy '*' --connect-timeout 2 -I https://github.com",
                bypass,
                0,
            ),
            approved_first_request_id: approved_first_lifecycle.request_id.to_string(),
            approved_cached_request_id: approved_cached_lifecycle.request_id.to_string(),
            unknown_request_id: unknown_lifecycle.request_id.to_string(),
            real_public_request_id: real_public_lifecycle.request_id.to_string(),
            approved_first_proxy_ms: total_latency_ms(&approved_first_lifecycle),
            approved_cached_proxy_ms: total_latency_ms(&approved_cached_lifecycle),
            unknown_proxy_ms: total_latency_ms(&unknown_lifecycle),
            real_public_proxy_ms: total_latency_ms(&real_public_lifecycle),
        },
    )?;
    println!("ZitPit smoke test passed.");
    Ok(())
}

async fn demo_build_timings() -> Result<()> {
    let paths = DemoPaths::load();
    fs::create_dir_all(&paths.root)?;
    fs::create_dir_all(&paths.ssh_dir)?;
    paths.runtime.ensure_dirs()?;
    let metadata = ensure_demo_setup_metadata(&paths, None)?;
    write_env_file(&paths, &metadata)?;

    let first_build_ms = timed_compose_build(&paths, true)?;
    let warm_build_ms = timed_compose_build(&paths, false)?;
    let no_op_build_ms = timed_compose_build(&paths, false)?;
    let summary = BuildTimingSummary {
        first_build_ms,
        warm_build_ms,
        no_op_build_ms,
    };
    write_json_report(&paths.last_build_report(), &summary)?;
    println!(
        "Docker build timings\n  first_build_ms: {}\n  warm_build_ms: {}\n  no_op_build_ms: {}",
        summary.first_build_ms, summary.warm_build_ms, summary.no_op_build_ms
    );
    Ok(())
}

fn seed_approved_repo(paths: &DemoPaths) -> Result<()> {
    if paths.approved_upstream_repo_root().join("HEAD").exists()
        && paths.unknown_upstream_repo_root().join("HEAD").exists()
    {
        return Ok(());
    }

    seed_demo_repo(
        &paths.root.join("seed-approved-workdir"),
        &paths.approved_upstream_repo_root(),
        "# ZitPit Demo Approved Repo\n\nThis repo is preapproved for the local demo.\n",
    )?;
    seed_demo_repo(
        &paths.root.join("seed-unknown-workdir"),
        &paths.unknown_upstream_repo_root(),
        "# ZitPit Demo Unknown Repo\n\nThis repo simulates a newly requested upstream.\n",
    )?;
    Ok(())
}

fn write_env_file(paths: &DemoPaths, metadata: &DemoSetupMetadata) -> Result<()> {
    let content = format!(
        concat!(
            "ZITPIT_DATA_DIR={data_dir}\n",
            "ZITPIT_SSH_PUBLIC_KEY={ssh_pub}\n",
            "ZITPIT_SSH_HOST_KEY={ssh_host_key}\n",
            "ZITPIT_APPROVED_REPO_URL={approved}\n",
            "ZITPIT_UNKNOWN_REPO_URL={unknown}\n",
            "ZITPIT_PROXY_URL=http://zitpit-gateway:3004\n",
            "ZITPIT_GIT_UPSTREAM_ROOT=/var/lib/zitpit/git/upstream\n",
            "DATABASE_URL=postgres://zitpit:zitpit@postgres:5432/zitpit\n"
        ),
        data_dir = paths.runtime.data_dir.canonicalize()?.display(),
        ssh_pub = metadata.staged_public_key.display(),
        ssh_host_key = metadata.server_host_key.display(),
        approved = paths.approved_source,
        unknown = paths.unknown_source,
    );
    fs::write(&paths.env_file, content)?;
    Ok(())
}

async fn seed_manifest_and_node(paths: &DemoPaths) -> Result<()> {
    let client = Client::new();
    let approved_target = run_capture(
        Command::new("git")
            .arg("--git-dir")
            .arg(paths.approved_upstream_repo_root())
            .args(["rev-parse", "HEAD"]),
    )?;

    client
        .post(format!("{DEMO_MANIFEST_BASE}/api/v1/manifest/promote"))
        .json(&json!({
            "coordinate": {
                "ecosystem": "git",
                "source": paths.approved_source,
                "requested_selector": "git-smart-http",
                "selector_kind": "floating"
            },
            "resolved_target": approved_target.trim(),
            "metadata": {
                "seeded_by": "xtask",
                "repo_kind": "approved_demo"
            }
        }))
        .send()
        .await?
        .error_for_status()?;

    client
        .post(format!("{DEMO_NODE_BASE}/api/v1/node/bootstrap"))
        .json(&json!({
            "node_id": "demo-node-1",
            "hostname": "workspace-ssh",
            "user_label": "demo-engineer"
        }))
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

async fn wait_for(url: &str) -> Result<()> {
    let client = Client::new();
    for _ in 0..120 {
        if let Ok(response) = client.get(url).send().await {
            if response.status().is_success() {
                return Ok(());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    bail!("timed out waiting for {url}");
}

fn print_ssh_config(metadata: &DemoSetupMetadata) {
    println!("{}", render_ssh_config(metadata));
}

fn render_ssh_config(metadata: &DemoSetupMetadata) -> String {
    format!(
        "Host {DEMO_SSH_ALIAS}\n  HostName 127.0.0.1\n  Port {DEMO_SSH_PORT}\n  User zitpit\n  IdentityFile {}\n  IdentitiesOnly yes\n  HostKeyAlias {DEMO_SSH_HOST_KEY_ALIAS}\n  StrictHostKeyChecking accept-new",
        metadata.client_private_key.display()
    )
}

fn git_smart_http_probe_command(source_url: &str) -> String {
    format!(
        "curl -sS --proxy http://zitpit-gateway:3004 -H 'Git-Protocol: version=2' -D - -o - -w '\\nZITPIT_HTTP_STATUS:%{{http_code}}\\n' '{source_url}/info/refs?service=git-upload-pack'"
    )
}

fn print_setup_completion(metadata: &DemoSetupMetadata) -> Result<()> {
    println!();
    println!("ZitPit does not edit your local SSH config automatically.");
    println!("Paste this into ~/.ssh/config:");
    println!();
    print_ssh_config(metadata);
    println!();
    println!("Server host fingerprint:");
    println!("  {}", server_host_fingerprint(metadata)?);
    println!();
    println!("Next steps:");
    println!("  1. Paste the SSH config block into ~/.ssh/config");
    println!("  2. Run: ssh {DEMO_SSH_ALIAS}");
    Ok(())
}

fn server_host_fingerprint(metadata: &DemoSetupMetadata) -> Result<String> {
    Ok(run_capture(
        Command::new("ssh-keygen")
            .arg("-lf")
            .arg(&metadata.server_host_public_key),
    )?
    .trim()
    .to_string())
}

fn demo_ssh_base(metadata: &DemoSetupMetadata, known_hosts_file: &Path) -> Result<Vec<String>> {
    Ok(vec![
        "-i".to_string(),
        metadata
            .client_private_key
            .to_str()
            .context("ssh key path")?
            .to_string(),
        "-o".to_string(),
        "IdentitiesOnly=yes".to_string(),
        "-o".to_string(),
        format!("HostKeyAlias={DEMO_SSH_HOST_KEY_ALIAS}"),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        format!("UserKnownHostsFile={}", known_hosts_file.display()),
        "-p".to_string(),
        DEMO_SSH_PORT.to_string(),
        "zitpit@127.0.0.1".to_string(),
    ])
}

fn clear_approved_demo_cache(paths: &DemoPaths) -> Result<()> {
    let cache_dir = paths
        .runtime
        .git_approved_root
        .join(safe_repo_dir(&paths.approved_source));
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir)
            .with_context(|| format!("remove demo approved cache {}", cache_dir.display()))?;
    }
    Ok(())
}

fn safe_repo_dir(source_url: &str) -> String {
    digest_for(source_url)[..16].to_string()
}

fn reset_demo_state(paths: &DemoPaths) -> Result<()> {
    if paths.runtime.data_dir.exists() {
        remove_demo_path(&paths.runtime.data_dir).with_context(|| {
            format!(
                "remove existing demo runtime state {}",
                paths.runtime.data_dir.display()
            )
        })?;
    }
    Ok(())
}

fn cleanup_demo_runtime_contents(paths: &DemoPaths) -> Result<()> {
    if !paths.runtime.data_dir.exists() {
        return Ok(());
    }
    let runtime_dir = "/var/lib/zitpit";
    let service_name = "zitpit-gateway";
    let status = docker_command()
        .args(["compose", "--env-file"])
        .arg(&paths.env_file)
        .args([
            "-f",
            "compose.yaml",
            "exec",
            "-T",
            "-u",
            "0",
            service_name,
            "sh",
            "-lc",
            &format!("rm -rf {runtime_dir}/* {runtime_dir}/.[!.]* {runtime_dir}/..?* || true"),
        ])
        .status();

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn remove_demo_path(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            remove_demo_path_via_container(path).with_context(|| {
                format!("remove demo state {} via docker fallback", path.display())
            })?;
            fs::remove_dir_all(path).with_context(|| {
                format!("remove demo state {} after docker fallback", path.display())
            })
        }
        Err(error) => Err(error.into()),
    }
}

fn remove_demo_path_via_container(path: &Path) -> Result<()> {
    let absolute = path
        .canonicalize()
        .with_context(|| format!("canonicalize demo state path {}", path.display()))?;
    let parent = absolute
        .parent()
        .context("demo state path must have a parent directory")?;
    let leaf = absolute
        .file_name()
        .and_then(|name| name.to_str())
        .context("demo state path must end in a valid UTF-8 directory name")?;

    let mut command = docker_command();
    command
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/target", parent.display()))
        .args(["--entrypoint", "sh", "zitpit-service:dev", "-lc"])
        .arg(format!("rm -rf /target/{leaf}"));
    run_command(&mut command)
}

fn timed_compose_build(paths: &DemoPaths, no_cache: bool) -> Result<u128> {
    let start = Instant::now();
    let mut command = docker_command();
    command
        .args(["compose", "--env-file"])
        .arg(&paths.env_file)
        .args(["-f", "compose.yaml", "build"]);
    if no_cache {
        command.arg("--no-cache");
    }
    run_command(&mut command)?;
    Ok(start.elapsed().as_millis())
}

fn docker_command() -> Command {
    Command::new(resolve_docker_binary())
}

fn resolve_docker_binary() -> PathBuf {
    [
        std::env::var_os("DOCKER_BIN").map(PathBuf::from),
        Some(PathBuf::from("/opt/homebrew/bin/docker")),
        Some(PathBuf::from("/usr/local/bin/docker")),
        std::env::var_os("PATH").map(|_| PathBuf::from("docker")),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| candidate == Path::new("docker") || candidate.exists())
    .unwrap_or_else(|| PathBuf::from("docker"))
}

fn seed_demo_repo(workdir: &Path, bare: &Path, readme: &str) -> Result<()> {
    if let Some(parent) = bare.parent() {
        fs::create_dir_all(parent)?;
    }
    if workdir.exists() {
        fs::remove_dir_all(workdir)?;
    }
    if bare.exists() {
        fs::remove_dir_all(bare)?;
    }
    fs::create_dir_all(workdir)?;
    run_command(
        Command::new("git")
            .arg("init")
            .arg("-b")
            .arg("main")
            .arg(workdir),
    )?;
    fs::write(workdir.join("README.md"), readme)?;
    run_command(Command::new("git").arg("-C").arg(workdir).args([
        "config",
        "user.email",
        "demo@zitpit.local",
    ]))?;
    run_command(Command::new("git").arg("-C").arg(workdir).args([
        "config",
        "user.name",
        "ZitPit Demo",
    ]))?;
    run_command(
        Command::new("git")
            .arg("-C")
            .arg(workdir)
            .args(["add", "."]),
    )?;
    run_command(Command::new("git").arg("-C").arg(workdir).args([
        "commit",
        "-m",
        "seed demo repo",
    ]))?;
    run_command(
        Command::new("git")
            .args(["clone", "--bare"])
            .arg(workdir)
            .arg(bare),
    )?;
    Ok(())
}

fn run_command(command: &mut Command) -> Result<()> {
    let status = command.status().context("run command")?;
    if status.success() {
        Ok(())
    } else {
        bail!("command failed with status {status}");
    }
}

fn run_capture(command: &mut Command) -> Result<String> {
    let output = command.output().context("capture command")?;
    if !output.status.success() {
        bail!(
            "command failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn write_json_report<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json).with_context(|| format!("write report {}", path.display()))
}

fn workspace_service_command(paths: &DemoPaths, shell_command: &str) -> Result<()> {
    let output = docker_command()
        .args(["compose", "--env-file"])
        .arg(&paths.env_file)
        .args([
            "-f",
            "compose.yaml",
            "exec",
            "-T",
            "workspace-ssh",
            "bash",
            "-lc",
            shell_command,
        ])
        .output()
        .context("run workspace service command")?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "workspace service command failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn find_git_lifecycle_since(
    client: &AdminClient,
    source_url: &str,
    started_at: chrono::DateTime<chrono::Utc>,
) -> Result<CapturedRequest> {
    for _ in 0..60 {
        let snapshot = client.snapshot().await?;
        if let Some(request) = snapshot.activity.iter().find(|request| {
            request.trace.received_at >= started_at
                && request
                    .artifact_key
                    .as_ref()
                    .map(|key| key.source == source_url)
                    .unwrap_or(false)
        }) {
            return Ok(request.clone());
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    bail!("timed out waiting for git lifecycle record after {started_at}")
}

fn format_git_lifecycle_report(label: &str, request: &CapturedRequest) -> String {
    let trace = &request.trace;
    let decision_latency = duration_ms(trace.received_at, trace.decision_at);
    let completion_latency = match trace.decision_at {
        Some(decision_at) => trace
            .completed_at
            .map(|completed_at| duration_ms(decision_at, Some(completed_at)))
            .unwrap_or(None),
        None => None,
    };

    let mut lines = vec![
        format!("Git lifecycle report: {label}"),
        format!("  request_id: {}", request.request_id),
        format!(
            "  authority: {} {}",
            request.observation.scheme, request.observation.authority
        ),
        format!("  path: {}", request.observation.path),
        format!("  method: {}", request.observation.method),
        format!("  proxy_action: {:?}", request.proxy_action),
        format!("  decision_reason: {}", request.decision_reason),
        format!(
            "  peer_addr: {}",
            trace.peer_addr.as_deref().unwrap_or("<unknown>")
        ),
        format!(
            "  local_addr: {}",
            trace.local_addr.as_deref().unwrap_or("<unknown>")
        ),
        format!("  received_at: {}", trace.received_at.to_rfc3339()),
        format!(
            "  decision_at: {}",
            trace
                .decision_at
                .map(|ts| ts.to_rfc3339())
                .unwrap_or_else(|| "<missing>".to_string())
        ),
        format!(
            "  completed_at: {}",
            trace
                .completed_at
                .map(|ts| ts.to_rfc3339())
                .unwrap_or_else(|| "<missing>".to_string())
        ),
        format!(
            "  decision_latency_ms: {}",
            decision_latency
                .map(|ms| ms.to_string())
                .unwrap_or_else(|| "<missing>".to_string())
        ),
        format!(
            "  completion_latency_ms: {}",
            completion_latency
                .map(|ms| ms.to_string())
                .unwrap_or_else(|| "<missing>".to_string())
        ),
        format!("  stored_body: {}", request.stored_body),
        format!(
            "  client_outcome: {}",
            request
                .client_outcome
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| "<missing>".to_string())
        ),
    ];

    if let Some(key) = &request.artifact_key {
        lines.push(format!("  artifact_source: {}", key.source));
        lines.push(format!("  artifact_selector: {}", key.requested_selector));
    }

    lines.push("  trace_events:".to_string());
    for event in &trace.events {
        lines.push(format!(
            "    - {:?} @ {} :: {}",
            event.kind,
            event.at.to_rfc3339(),
            event.detail
        ));
    }
    lines.join("\n")
}

fn format_latency_comparison(
    approved_first: &CapturedRequest,
    approved_first_elapsed_ms: u128,
    approved_cached: &CapturedRequest,
    approved_cached_elapsed_ms: u128,
    unknown: &CapturedRequest,
    unknown_elapsed_ms: u128,
) -> String {
    let first_latency = approved_first
        .trace
        .completed_at
        .map(|completed| {
            completed
                .signed_duration_since(approved_first.trace.received_at)
                .num_milliseconds()
        })
        .unwrap_or_default();
    let cached_latency = approved_cached
        .trace
        .completed_at
        .map(|completed| {
            completed
                .signed_duration_since(approved_cached.trace.received_at)
                .num_milliseconds()
        })
        .unwrap_or_default();
    let unknown_latency = unknown
        .trace
        .completed_at
        .map(|completed| {
            completed
                .signed_duration_since(unknown.trace.received_at)
                .num_milliseconds()
        })
        .unwrap_or_default();
    format!(
        "Git latency comparison\n  approved_first_host_ms: {approved_first_elapsed_ms}\n  approved_first_proxy_ms: {first_latency}\n  approved_cache_hit_host_ms: {approved_cached_elapsed_ms}\n  approved_cache_hit_proxy_ms: {cached_latency}\n  unknown_pending_host_ms: {unknown_elapsed_ms}\n  unknown_pending_proxy_ms: {unknown_latency}"
    )
}

struct TimedCommandResult {
    output: std::process::Output,
    elapsed_ms: u128,
    started_at: chrono::DateTime<chrono::Utc>,
}

impl CommandSummary {
    fn from_timed_command(command: &str, result: &TimedCommandResult) -> Self {
        Self {
            command: command.to_string(),
            exit_code: result.output.status.code(),
            elapsed_ms: result.elapsed_ms,
            stdout: String::from_utf8_lossy(&result.output.stdout)
                .trim()
                .to_string(),
            stderr: String::from_utf8_lossy(&result.output.stderr)
                .trim()
                .to_string(),
        }
    }

    fn from_output(command: &str, output: std::process::Output, elapsed_ms: u128) -> Self {
        Self {
            command: command.to_string(),
            exit_code: output.status.code(),
            elapsed_ms,
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }
    }
}

fn run_ssh_timed(ssh_base: &[String], command: &str) -> Result<TimedCommandResult> {
    let started_at = chrono::Utc::now();
    let start = Instant::now();
    let output = Command::new("ssh")
        .args(ssh_base)
        .arg(command)
        .output()
        .with_context(|| format!("run ssh command: {command}"))?;
    Ok(TimedCommandResult {
        output,
        elapsed_ms: start.elapsed().as_millis(),
        started_at,
    })
}

fn split_ssh_invocation(ssh_base: &[String]) -> Result<(&[String], &str)> {
    let (ssh_target, ssh_options) = ssh_base
        .split_last()
        .context("ssh invocation must include a target host")?;
    Ok((ssh_options, ssh_target.as_str()))
}

fn run_ssh_interactive_timed(ssh_base: &[String], input: &str) -> Result<TimedCommandResult> {
    let started_at = chrono::Utc::now();
    let start = Instant::now();
    let (ssh_options, ssh_target) = split_ssh_invocation(ssh_base)?;
    let mut child = Command::new("ssh")
        .args(ssh_options)
        .arg("-tt")
        .arg(ssh_target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run interactive ssh session")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .context("write interactive ssh input")?;
    }

    let output = child
        .wait_with_output()
        .context("wait for interactive ssh session")?;
    Ok(TimedCommandResult {
        output,
        elapsed_ms: start.elapsed().as_millis(),
        started_at,
    })
}

fn duration_ms(
    start: chrono::DateTime<chrono::Utc>,
    end: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<i64> {
    end.map(|end| end.signed_duration_since(start).num_milliseconds())
}

fn total_latency_ms(request: &CapturedRequest) -> i64 {
    request
        .trace
        .completed_at
        .map(|completed| {
            completed
                .signed_duration_since(request.trace.received_at)
                .num_milliseconds()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    use chrono::Utc;
    use zitpit_config::RuntimePaths;
    use zitpit_core::{
        ArtifactKey, CapturedRequest, Classification, CodeIntent, Ecosystem, ProxyAction,
        ProxyTrace, ProxyTraceKind, RequestObservation, SelectorKind, TrafficLane,
    };

    use super::{
        DemoPaths, DemoSetupMetadata, format_git_lifecycle_report, load_setup_metadata,
        render_ssh_config, select_client_identity, split_ssh_invocation, write_env_file,
        write_json_report,
    };

    const WORKSPACE_ENTRYPOINT: &str = include_str!("../../deploy/workspace/entrypoint.sh");
    const PROTECTED_SESSION_SCRIPT: &str =
        include_str!("../../deploy/workspace/protected-session.sh");
    const PROTECTED_PROFILE_SCRIPT: &str =
        include_str!("../../deploy/workspace/zitpit-protected-profile.sh");
    const WORKSPACE_SSHD_CONFIG: &str = include_str!("../../deploy/workspace/sshd_config.zitpit");

    fn test_paths(name: &str) -> DemoPaths {
        let root = env::temp_dir().join(format!("zitpit-xtask-{name}-{}", uuid::Uuid::new_v4()));
        DemoPaths {
            runtime: RuntimePaths::new(root.join("state")),
            ssh_dir: root.join("ssh"),
            env_file: root.join("demo.env"),
            approved_source: "http://github.com/jeppsontaylor/approved.git".to_string(),
            unknown_source: "http://github.com/jeppsontaylor/unknown.git".to_string(),
            real_public_source: "http://github.com/axios/axios.git".to_string(),
            root,
        }
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write file");
    }

    #[test]
    fn demo_paths_use_expected_repo_shape() {
        let paths = DemoPaths::load();
        let root = paths.approved_upstream_repo_root();
        assert!(root.ends_with("jeppsontaylor/approved.git"));
        assert!(
            paths
                .unknown_upstream_repo_root()
                .ends_with("jeppsontaylor/unknown.git")
        );
    }

    #[test]
    fn git_lifecycle_report_includes_trace_and_timing() {
        let request = CapturedRequest {
            request_id: uuid::Uuid::new_v4(),
            observation: RequestObservation {
                request_id: uuid::Uuid::new_v4(),
                observed_at: Utc::now(),
                scheme: "http".to_string(),
                authority: "github.com".to_string(),
                path: "/jeppsontaylor/unknown.git/info/refs".to_string(),
                method: "GET".to_string(),
                user_agent: Some("git/2.47".to_string()),
                headers: Default::default(),
                selector_hint: None,
            },
            classification: Classification {
                lane: TrafficLane::CodeIntake,
                ecosystem: Some(Ecosystem::Git),
                intent: CodeIntent::GitRemote,
                reason: "known Git hosting domain".to_string(),
                confidence: 95,
                requires_quarantine: true,
                host_family: Some("github.com".to_string()),
            },
            proxy_action: ProxyAction::Pending,
            status_code: Some(403),
            bytes_in: Some(0),
            bytes_out: Some(0),
            stored_body: true,
            client_outcome: Some(zitpit_core::ClientVisibleOutcome::TemporaryFailure),
            decision_reason: "fail closed".to_string(),
            artifact_key: Some(ArtifactKey {
                ecosystem: Ecosystem::Git,
                source: "http://github.com/jeppsontaylor/unknown.git".to_string(),
                requested_selector: "git-smart-http".to_string(),
                selector_kind: SelectorKind::Floating,
            }),
            trace: ProxyTrace::new(
                Some("127.0.0.1:55555".to_string()),
                Some("127.0.0.1:3004".to_string()),
                Utc::now(),
            )
            .with_decision("pending")
            .with_event(ProxyTraceKind::Pending, "held pending approval")
            .with_completion("pending"),
        };

        let report = format_git_lifecycle_report("git-lifecycle", &request);
        assert!(report.contains("Git lifecycle report"));
        assert!(report.contains("peer_addr: 127.0.0.1:55555"));
        assert!(report.contains("local_addr: 127.0.0.1:3004"));
        assert!(report.contains("decision_latency_ms"));
        assert!(report.contains("trace_events"));
        assert!(report.contains("Pending"));
    }

    #[test]
    fn split_ssh_invocation_returns_options_and_target() {
        let ssh_base = vec![
            "-i".to_string(),
            "/tmp/demo-key".to_string(),
            "-p".to_string(),
            "42222".to_string(),
            "zitpit@127.0.0.1".to_string(),
        ];

        let (options, target) = split_ssh_invocation(&ssh_base).expect("split ssh invocation");

        assert_eq!(options, &ssh_base[..ssh_base.len() - 1]);
        assert_eq!(target, "zitpit@127.0.0.1");
    }

    #[test]
    fn split_ssh_invocation_rejects_empty_base() {
        let error = split_ssh_invocation(&[]).expect_err("empty ssh invocation should fail");
        assert!(error.to_string().contains("target host"));
    }

    #[test]
    fn workspace_entrypoint_repairs_home_ownership_for_ide_bootstrap() {
        assert!(WORKSPACE_ENTRYPOINT.contains("chown zitpit:zitpit /home/zitpit"));
        assert!(
            WORKSPACE_ENTRYPOINT
                .contains("chown -R zitpit:zitpit /home/zitpit/.ssh /home/zitpit/workspace")
        );
    }

    #[test]
    fn workspace_entrypoint_sources_protected_profile_for_interactive_bash_shells() {
        assert!(WORKSPACE_ENTRYPOINT.contains("/etc/bash.bashrc"));
        assert!(WORKSPACE_ENTRYPOINT.contains("source /etc/profile.d/zitpit-protected.sh"));
    }

    #[test]
    fn protected_session_normalizes_dumb_term_for_tmux() {
        assert!(PROTECTED_SESSION_SCRIPT.contains("normalize_term"));
        assert!(PROTECTED_SESSION_SCRIPT.contains("\"\"|dumb|unknown"));
        assert!(PROTECTED_SESSION_SCRIPT.contains("xterm-256color"));
    }

    #[test]
    fn protected_session_resets_terminal_identity_on_exit() {
        assert!(PROTECTED_SESSION_SCRIPT.contains("trap reset_terminal_identity EXIT"));
        assert!(PROTECTED_SESSION_SCRIPT.contains("emit_osc \"111\""));
        assert!(PROTECTED_SESSION_SCRIPT.contains("emit_osc \"110\""));
        assert!(PROTECTED_SESSION_SCRIPT.contains("emit_osc \"112\""));
    }

    #[test]
    fn protected_profile_does_not_export_prompt_command() {
        assert!(!PROTECTED_PROFILE_SCRIPT.contains("export PS1 PROMPT_COMMAND"));
        assert!(
            PROTECTED_PROFILE_SCRIPT.contains("PROMPT_COMMAND=\"_zitpit_emit_terminal_identity")
        );
    }

    #[test]
    fn select_client_identity_prefers_ed25519() {
        let paths = test_paths("identity-priority");
        let home = paths.root.join("home");
        write_file(&home.join(".ssh/id_rsa"), "rsa");
        write_file(&home.join(".ssh/id_rsa.pub"), "rsa pub");
        write_file(&home.join(".ssh/id_ed25519"), "ed25519");
        write_file(&home.join(".ssh/id_ed25519.pub"), "ed25519 pub");

        let identity =
            select_client_identity(&paths, None, Some(home.as_path())).expect("select identity");
        assert_eq!(identity.private_key, home.join(".ssh/id_ed25519"));
        assert_eq!(identity.public_key, home.join(".ssh/id_ed25519.pub"));
        assert!(!identity.generated);
    }

    #[test]
    fn select_client_identity_honors_explicit_override() {
        let paths = test_paths("identity-override");
        let private_key = paths.root.join("custom/id_override");
        write_file(&private_key, "private");
        write_file(
            &PathBuf::from(format!("{}.pub", private_key.display())),
            "public",
        );

        let identity =
            select_client_identity(&paths, Some(private_key.as_path()), None).expect("override");
        assert_eq!(
            identity.private_key,
            private_key.canonicalize().expect("canonical private key")
        );
        assert!(!identity.generated);
    }

    #[test]
    fn render_ssh_config_uses_safe_local_alias() {
        let metadata = DemoSetupMetadata {
            client_private_key: PathBuf::from("/tmp/zitpit-client"),
            staged_public_key: PathBuf::from("/tmp/authorized_key.pub"),
            server_host_key: PathBuf::from("/tmp/ssh_host_ed25519_key"),
            server_host_public_key: PathBuf::from("/tmp/ssh_host_ed25519_key.pub"),
            generated_client_key: false,
        };

        let rendered = render_ssh_config(&metadata);
        assert!(rendered.contains("Host zitpit"));
        assert!(rendered.contains("User zitpit"));
        assert!(rendered.contains("HostKeyAlias zitpit-local"));
        assert!(rendered.contains("StrictHostKeyChecking accept-new"));
    }

    #[test]
    fn select_client_identity_generates_dedicated_key_when_needed() {
        let paths = test_paths("identity-generated");
        let home = paths.root.join("home");
        fs::create_dir_all(&paths.ssh_dir).expect("create ssh dir");

        let identity =
            select_client_identity(&paths, None, Some(home.as_path())).expect("generated key");
        assert!(identity.generated);
        assert!(identity.private_key.exists());
        assert!(identity.public_key.exists());
        assert_eq!(identity.private_key, paths.generated_client_private_key());
        assert_eq!(identity.public_key, paths.generated_client_public_key());
    }

    #[test]
    fn workspace_sshd_config_disables_password_auth() {
        assert!(WORKSPACE_SSHD_CONFIG.contains("HostKey /run/zitpit/ssh_host_ed25519_key"));
        assert!(WORKSPACE_SSHD_CONFIG.contains("PasswordAuthentication no"));
        assert!(WORKSPACE_SSHD_CONFIG.contains("KbdInteractiveAuthentication no"));
        assert!(WORKSPACE_SSHD_CONFIG.contains("ChallengeResponseAuthentication no"));
        assert!(WORKSPACE_SSHD_CONFIG.contains("PubkeyAuthentication yes"));
        assert!(WORKSPACE_SSHD_CONFIG.contains("AllowUsers zitpit"));
        assert!(WORKSPACE_SSHD_CONFIG.contains("AuthorizedKeysFile .ssh/authorized_keys"));
    }

    #[test]
    fn setup_metadata_and_env_preserve_selected_paths() {
        let paths = test_paths("metadata");
        fs::create_dir_all(&paths.root).expect("create root");
        fs::create_dir_all(&paths.ssh_dir).expect("create ssh dir");
        paths.runtime.ensure_dirs().expect("runtime dirs");

        let client_private_key = paths.root.join("keys/client");
        let staged_public_key = paths.root.join("keys/authorized_key.pub");
        let server_host_key = paths.root.join("keys/ssh_host_ed25519_key");
        let server_host_public_key = paths.root.join("keys/ssh_host_ed25519_key.pub");
        write_file(&client_private_key, "private");
        write_file(&staged_public_key, "public");
        write_file(&server_host_key, "host private");
        write_file(&server_host_public_key, "host public");

        let metadata = DemoSetupMetadata {
            client_private_key: client_private_key
                .canonicalize()
                .expect("client private key"),
            staged_public_key: staged_public_key.canonicalize().expect("staged public key"),
            server_host_key: server_host_key.canonicalize().expect("server host key"),
            server_host_public_key: server_host_public_key
                .canonicalize()
                .expect("server host public key"),
            generated_client_key: false,
        };
        write_json_report(&paths.setup_metadata(), &metadata).expect("write setup metadata");
        let loaded = load_setup_metadata(&paths).expect("load setup metadata");
        assert_eq!(loaded, metadata);

        write_env_file(&paths, &metadata).expect("write env file");
        let env_contents = fs::read_to_string(&paths.env_file).expect("read env file");
        assert!(env_contents.contains(&format!(
            "ZITPIT_SSH_PUBLIC_KEY={}",
            metadata.staged_public_key.display()
        )));
        assert!(env_contents.contains(&format!(
            "ZITPIT_SSH_HOST_KEY={}",
            metadata.server_host_key.display()
        )));
    }
}
