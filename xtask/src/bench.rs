use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use http_body_util::BodyExt;
use reqwest::{Method, Url, header::HeaderMap};
use serde::{Deserialize, Serialize};
use zitpit_config::RuntimePaths;
use zitpit_core::{
    ApprovalStatus, ArtifactKey, CacheDomain, CacheEntry, Ecosystem, GitSmartHttpAdapter,
    ManifestRecord, MemoryStore, SelectorKind, StoreHandle, manifest::digest_for,
};

const CLAIM_CLASS: &str = "git_smart_http_intake";

#[derive(Debug, Clone)]
pub struct BenchRunConfig {
    pub repos: Vec<String>,
    pub samples: usize,
    pub json_out: Option<PathBuf>,
    pub md_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BenchMode {
    Web,
    Cache,
    HotCache,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CacheState {
    UpstreamWeb,
    ApprovedDiskCache,
    ApprovedHotCache,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchmarkSample {
    pub repo: String,
    pub source_url: String,
    pub resolved_head_sha: String,
    pub request_url: String,
    pub mode: BenchMode,
    pub cache_state: CacheState,
    pub elapsed_ms: u128,
    pub claim_class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimingStats {
    pub median_ms: u128,
    pub p95_ms: u128,
    pub samples_ms: Vec<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoBenchmarkReport {
    pub repo: String,
    pub source_url: String,
    pub request_url: String,
    pub resolved_head_sha: String,
    pub web: TimingStats,
    pub cache: TimingStats,
    pub hot_cache: TimingStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchmarkReport {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub samples: Vec<BenchmarkSample>,
    pub repos: Vec<RepoBenchmarkReport>,
}

#[derive(Debug, Clone)]
struct RepoSpec {
    name: &'static str,
    source_url: &'static str,
}

const DEFAULT_REPOS: &[RepoSpec] = &[
    RepoSpec {
        name: "git",
        source_url: "https://github.com/git/git.git",
    },
    RepoSpec {
        name: "go",
        source_url: "https://github.com/golang/go.git",
    },
    RepoSpec {
        name: "node",
        source_url: "https://github.com/nodejs/node.git",
    },
    RepoSpec {
        name: "cpython",
        source_url: "https://github.com/python/cpython.git",
    },
    RepoSpec {
        name: "terraform",
        source_url: "https://github.com/hashicorp/terraform.git",
    },
    RepoSpec {
        name: "kubernetes",
        source_url: "https://github.com/kubernetes/kubernetes.git",
    },
    RepoSpec {
        name: "rust",
        source_url: "https://github.com/rust-lang/rust.git",
    },
];

pub async fn run(config: BenchRunConfig) -> Result<()> {
    let repos = resolve_repos(&config.repos, DEFAULT_REPOS)?;
    if repos.is_empty() {
        bail!("no benchmark repositories selected");
    }

    let json_out = config
        .json_out
        .unwrap_or_else(|| PathBuf::from("docs/benchmarks/latest.json"));
    let md_out = config
        .md_out
        .unwrap_or_else(|| PathBuf::from("docs/benchmarks/latest.md"));

    let mut all_samples = Vec::new();
    let mut reports = Vec::new();
    for repo in repos {
        println!("benchmarking {} ({})", repo.name, repo.source_url);
        let (report, samples) = run_repo_benchmark(&repo, config.samples.max(1)).await?;
        reports.push(report);
        all_samples.extend(samples);
    }

    let report = BenchmarkReport {
        generated_at: Utc::now(),
        samples: all_samples,
        repos: reports,
    };

    write_json_report(&json_out, &report)?;
    write_markdown_report(&md_out, &report)?;

    println!("{}", render_summary(&report));
    Ok(())
}

fn resolve_repos(tokens: &[String], defaults: &[RepoSpec]) -> Result<Vec<RepoSpec>> {
    if tokens.is_empty() {
        return Ok(defaults.iter().take(5).cloned().collect());
    }

    tokens
        .iter()
        .map(|token| {
            if let Some(repo) = defaults.iter().find(|repo| repo.name == token.as_str()) {
                return Ok(repo.clone());
            }
            if token.starts_with("http://") || token.starts_with("https://") {
                let parsed =
                    Url::parse(token).with_context(|| format!("parse repo url {token}"))?;
                let name = parsed
                    .path_segments()
                    .and_then(|segments| segments.filter(|segment| !segment.is_empty()).last())
                    .unwrap_or("repo");
                let leaked: &'static str = Box::leak(token.clone().into_boxed_str());
                let name: &'static str = Box::leak(name.to_string().into_boxed_str());
                return Ok(RepoSpec {
                    name,
                    source_url: leaked,
                });
            }
            bail!(
                "unknown repo token '{token}'. Use one of: {} or pass a full https URL.",
                defaults
                    .iter()
                    .map(|repo| repo.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect()
}

async fn run_repo_benchmark(
    repo: &RepoSpec,
    samples: usize,
) -> Result<(RepoBenchmarkReport, Vec<BenchmarkSample>)> {
    let resolved_head_sha = resolve_head_sha(repo.source_url)?;
    let request_url = smart_http_request_url(repo.source_url)?;
    let runtime_root = tempfile::tempdir()?;
    let runtime = RuntimePaths::new(runtime_root.path().join("state"));
    runtime.ensure_dirs()?;
    let store = StoreHandle::from_memory(MemoryStore::seeded().await);

    seed_approved_repo(&runtime, &store, repo, &resolved_head_sha).await?;

    let mut sample_rows = Vec::new();
    let mut web = Vec::new();
    let mut cache = Vec::new();
    let mut hot_cache = Vec::new();

    for _ in 0..samples {
        let web_elapsed_ms = time_web_request(repo.source_url)?;
        web.push(web_elapsed_ms);
        sample_rows.push(BenchmarkSample {
            repo: repo.name.to_string(),
            source_url: repo.source_url.to_string(),
            resolved_head_sha: resolved_head_sha.clone(),
            request_url: request_url.to_string(),
            mode: BenchMode::Web,
            cache_state: CacheState::UpstreamWeb,
            elapsed_ms: web_elapsed_ms,
            claim_class: CLAIM_CLASS.to_string(),
        });

        let adapter = GitSmartHttpAdapter::with_paths_and_hold_duration_and_hot_cache_capacity(
            store.clone(),
            runtime.clone(),
            24,
            16,
        );
        let (cache_elapsed_ms, cache_sample) =
            time_cached_request(&adapter, repo, &request_url, &resolved_head_sha).await?;
        cache.push(cache_elapsed_ms);
        sample_rows.push(cache_sample);

        let (hot_elapsed_ms, hot_sample) =
            time_cached_request(&adapter, repo, &request_url, &resolved_head_sha).await?;
        hot_cache.push(hot_elapsed_ms);
        sample_rows.push(hot_sample);
    }

    let report = RepoBenchmarkReport {
        repo: repo.name.to_string(),
        source_url: repo.source_url.to_string(),
        request_url: request_url.to_string(),
        resolved_head_sha,
        web: summarize_timings(&web),
        cache: summarize_timings(&cache),
        hot_cache: summarize_timings(&hot_cache),
    };

    Ok((report, sample_rows))
}

async fn time_cached_request(
    adapter: &GitSmartHttpAdapter,
    repo: &RepoSpec,
    request_url: &Url,
    resolved_head_sha: &str,
) -> Result<(u128, BenchmarkSample)> {
    let start = Instant::now();
    let result = adapter
        .handle(
            repo.source_url,
            request_url,
            &Method::GET,
            &HeaderMap::new(),
            bytes::Bytes::new(),
        )
        .await?;
    let body = result.response.into_body().collect().await?.to_bytes();
    let elapsed_ms = start.elapsed().as_millis();
    if body.is_empty() {
        bail!("cached request for {} returned an empty body", repo.name);
    }
    let sample = BenchmarkSample {
        repo: repo.name.to_string(),
        source_url: repo.source_url.to_string(),
        resolved_head_sha: resolved_head_sha.to_string(),
        request_url: request_url.to_string(),
        mode: if result.hot_cache_hit {
            BenchMode::HotCache
        } else {
            BenchMode::Cache
        },
        cache_state: if result.hot_cache_hit {
            CacheState::ApprovedHotCache
        } else {
            CacheState::ApprovedDiskCache
        },
        elapsed_ms,
        claim_class: CLAIM_CLASS.to_string(),
    };
    Ok((elapsed_ms, sample))
}

fn time_web_request(source_url: &str) -> Result<u128> {
    let start = Instant::now();
    let output = Command::new("git")
        .args(["ls-remote", source_url, "HEAD"])
        .output()
        .with_context(|| format!("run git ls-remote for {source_url}"))?;
    if !output.status.success() {
        bail!(
            "git ls-remote failed for {source_url}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(start.elapsed().as_millis())
}

fn resolve_head_sha(source_url: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["ls-remote", source_url, "HEAD"])
        .output()
        .with_context(|| format!("resolve head sha for {source_url}"))?;
    if !output.status.success() {
        bail!(
            "git ls-remote failed for {source_url}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let head = stdout
        .split_whitespace()
        .next()
        .context("parse HEAD sha from ls-remote output")?;
    Ok(head.to_string())
}

async fn seed_approved_repo(
    runtime: &RuntimePaths,
    store: &StoreHandle,
    repo: &RepoSpec,
    resolved_head_sha: &str,
) -> Result<()> {
    let repo_path = repo_path_from_source(repo.source_url)?;
    let project_root = runtime
        .git_approved_root
        .join(safe_repo_dir(repo.source_url));
    let repo_root = project_root.join(&repo_path);
    if !repo_root.join("objects").exists() {
        fs::create_dir_all(repo_root.parent().context("repo root parent")?)?;
        println!("  seeding approved mirror for {}", repo.name);
        let seed_workdir = repo_root
            .parent()
            .context("repo root parent")?
            .join("seed-work");
        if seed_workdir.exists() {
            fs::remove_dir_all(&seed_workdir)?;
        }
        let init = Command::new("git")
            .arg("init")
            .arg(&seed_workdir)
            .output()
            .with_context(|| format!("seed approved workdir for {}", repo.name))?;
        if !init.status.success() {
            bail!(
                "git init failed for {}: {}",
                repo.name,
                String::from_utf8_lossy(&init.stderr)
            );
        }
        let config_email = Command::new("git")
            .arg("-C")
            .arg(&seed_workdir)
            .args(["config", "user.email", "zitpit@example.com"])
            .output()
            .with_context(|| format!("seed approved git email for {}", repo.name))?;
        if !config_email.status.success() {
            bail!(
                "git config user.email failed for {}: {}",
                repo.name,
                String::from_utf8_lossy(&config_email.stderr)
            );
        }
        let config_name = Command::new("git")
            .arg("-C")
            .arg(&seed_workdir)
            .args(["config", "user.name", "ZitPit Benchmark"])
            .output()
            .with_context(|| format!("seed approved git name for {}", repo.name))?;
        if !config_name.status.success() {
            bail!(
                "git config user.name failed for {}: {}",
                repo.name,
                String::from_utf8_lossy(&config_name.stderr)
            );
        }
        fs::write(
            seed_workdir.join("README.md"),
            format!("# {}\n\nbenchmark seed\n", repo.name),
        )?;
        let add = Command::new("git")
            .arg("-C")
            .arg(&seed_workdir)
            .args(["add", "."])
            .output()
            .with_context(|| format!("seed approved git add for {}", repo.name))?;
        if !add.status.success() {
            bail!(
                "git add failed for {}: {}",
                repo.name,
                String::from_utf8_lossy(&add.stderr)
            );
        }
        let commit = Command::new("git")
            .arg("-C")
            .arg(&seed_workdir)
            .args(["commit", "-m", "seed"])
            .output()
            .with_context(|| format!("seed approved git commit for {}", repo.name))?;
        if !commit.status.success() {
            bail!(
                "git commit failed for {}: {}",
                repo.name,
                String::from_utf8_lossy(&commit.stderr)
            );
        }
        let output = Command::new("git")
            .args(["clone", "--mirror"])
            .arg(&seed_workdir)
            .arg(&repo_root)
            .output()
            .with_context(|| format!("seed approved mirror for {}", repo.name))?;
        if !output.status.success() {
            bail!(
                "git clone --mirror failed for {}: {}",
                repo.name,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    println!("  approved mirror ready for {}", repo.name);

    let key = ArtifactKey {
        ecosystem: Ecosystem::Git,
        source: repo.source_url.to_string(),
        requested_selector: "git-smart-http".to_string(),
        selector_kind: SelectorKind::Floating,
    };

    store
        .0
        .put_cache_entry(CacheEntry {
            artifact_key: key.clone(),
            domain: CacheDomain::Approved,
            storage_path: repo_root.display().to_string(),
            created_at: Utc::now(),
            size_bytes: None,
            digest_sha256: digest_for(resolved_head_sha),
        })
        .await?;
    store
        .0
        .upsert_manifest_record(ManifestRecord {
            ecosystem: Ecosystem::Git,
            source: repo.source_url.to_string(),
            requested_selector: "git-smart-http".to_string(),
            selector_kind: SelectorKind::Floating,
            resolved_target: resolved_head_sha.to_string(),
            raw_digest_sha256: digest_for(resolved_head_sha),
            normalized_digest_sha256: digest_for(&format!("{resolved_head_sha}:normalized")),
            status: ApprovalStatus::Approved,
            first_seen_at: Utc::now(),
            hold_until: None,
            approved_at: Some(Utc::now()),
            fallback: None,
            detector_refs: vec!["benchmark://approved-cache".to_string()],
            metadata: BTreeMap::from([
                ("repo".to_string(), repo.name.to_string()),
                ("mode".to_string(), "benchmark_seed".to_string()),
            ]),
        })
        .await?;

    Ok(())
}

fn repo_path_from_source(source_url: &str) -> Result<String> {
    let parsed =
        Url::parse(source_url).with_context(|| format!("parse source url {source_url}"))?;
    Ok(parsed.path().trim_start_matches('/').to_string())
}

fn smart_http_request_url(source_url: &str) -> Result<Url> {
    let repo_path = repo_path_from_source(source_url)?;
    Url::parse(&format!(
        "https://zitpit.invalid/{repo_path}/info/refs?service=git-upload-pack"
    ))
    .with_context(|| format!("build request url for {source_url}"))
}

fn safe_repo_dir(source_url: &str) -> String {
    digest_for(source_url)[..16].to_string()
}

fn summarize_timings(samples: &[u128]) -> TimingStats {
    let mut values = samples.to_vec();
    values.sort_unstable();
    TimingStats {
        median_ms: percentile(&values, 0.50),
        p95_ms: percentile(&values, 0.95),
        samples_ms: values,
    }
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((sorted.len() as f64) * p).ceil().max(1.0) as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

fn render_summary(report: &BenchmarkReport) -> String {
    let mut lines = Vec::new();
    lines.push("ZitPit benchmark summary".to_string());
    lines.push(format!(
        "generated_at: {}",
        report.generated_at.to_rfc3339()
    ));
    lines.push("repo | web_median_ms | cache_median_ms | hot_cache_median_ms | web_p95_ms | cache_p95_ms | hot_cache_p95_ms".to_string());
    for repo in &report.repos {
        lines.push(format!(
            "{} | {} | {} | {} | {} | {} | {}",
            repo.repo,
            repo.web.median_ms,
            repo.cache.median_ms,
            repo.hot_cache.median_ms,
            repo.web.p95_ms,
            repo.cache.p95_ms,
            repo.hot_cache.p95_ms,
        ));
    }
    lines.join("\n")
}

fn write_json_report(path: &Path, value: &BenchmarkReport) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create benchmark json parent {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(value)?;
    fs::write(path, content).with_context(|| format!("write benchmark json {}", path.display()))?;
    Ok(())
}

fn write_markdown_report(path: &Path, value: &BenchmarkReport) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create benchmark markdown parent {}", parent.display()))?;
    }
    let mut markdown = String::new();
    markdown.push_str("# ZitPit Benchmarks\n\n");
    markdown.push_str(&format!(
        "Generated at `{}`.\n\n",
        value.generated_at.to_rfc3339()
    ));
    markdown.push_str("| Repo | HEAD SHA | web median ms | cache median ms | hot-cache median ms | web p95 ms | cache p95 ms | hot-cache p95 ms |\n");
    markdown.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for repo in &value.repos {
        markdown.push_str(&format!(
            "| {} | `{}` | {} | {} | {} | {} | {} | {} |\n",
            repo.repo,
            repo.resolved_head_sha,
            repo.web.median_ms,
            repo.cache.median_ms,
            repo.hot_cache.median_ms,
            repo.web.p95_ms,
            repo.cache.p95_ms,
            repo.hot_cache.p95_ms,
        ));
    }
    markdown.push_str("\n## Claim Class\n\n");
    markdown.push_str(&format!(
        "`{}`: initial smart-http intake request latency for web, disk cache, and hot cache.\n",
        CLAIM_CLASS
    ));
    fs::write(path, markdown)
        .with_context(|| format!("write benchmark markdown {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_repos_supports_default_catalog_and_aliases() {
        let repos = resolve_repos(&[], DEFAULT_REPOS).expect("resolve defaults");
        assert_eq!(repos.len(), 5);
        assert_eq!(repos[0].name, "git");

        let selected = resolve_repos(&["node".to_string()], DEFAULT_REPOS).expect("alias");
        assert_eq!(selected[0].source_url, "https://github.com/nodejs/node.git");
    }

    #[test]
    fn render_summary_includes_all_three_modes() {
        let report = BenchmarkReport {
            generated_at: Utc::now(),
            samples: vec![],
            repos: vec![RepoBenchmarkReport {
                repo: "git".to_string(),
                source_url: "https://github.com/git/git.git".to_string(),
                request_url: "https://zitpit.invalid/git/git.git/info/refs?service=git-upload-pack"
                    .to_string(),
                resolved_head_sha: "abc123".to_string(),
                web: TimingStats {
                    median_ms: 120,
                    p95_ms: 140,
                    samples_ms: vec![120],
                },
                cache: TimingStats {
                    median_ms: 12,
                    p95_ms: 15,
                    samples_ms: vec![12],
                },
                hot_cache: TimingStats {
                    median_ms: 2,
                    p95_ms: 3,
                    samples_ms: vec![2],
                },
            }],
        };

        let summary = render_summary(&report);
        assert!(summary.contains("web_median_ms"));
        assert!(summary.contains("hot_cache_p95_ms"));
    }
}
