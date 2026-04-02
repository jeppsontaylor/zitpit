use crate::types::{Classification, CodeIntent, Ecosystem, RequestObservation, TrafficLane};

#[derive(Debug, Default)]
pub struct RequestClassifier;

impl RequestClassifier {
    pub fn classify(observation: &RequestObservation) -> Classification {
        let authority = observation.authority.to_ascii_lowercase();
        let authority_host = normalize_authority(&authority);
        let path = observation.path.to_ascii_lowercase();
        let user_agent = observation
            .user_agent
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();

        let (ecosystem, intent, lane, reason, confidence, requires_quarantine, host_family) =
            if is_git_host(&authority_host) {
                (
                    Some(Ecosystem::Git),
                    CodeIntent::GitRemote,
                    TrafficLane::CodeIntake,
                    "known Git hosting domain".to_string(),
                    95,
                    true,
                    Some(authority_host.clone()),
                )
            } else if is_npm_host(&authority_host) {
                (
                    Some(Ecosystem::Npm),
                    CodeIntent::Registry,
                    TrafficLane::CodeIntake,
                    "known npm registry host".to_string(),
                    95,
                    true,
                    Some("npm".to_string()),
                )
            } else if is_pypi_host(&authority_host) {
                (
                    Some(Ecosystem::Pypi),
                    CodeIntent::Registry,
                    TrafficLane::CodeIntake,
                    "known Python package host".to_string(),
                    95,
                    true,
                    Some("pypi".to_string()),
                )
            } else if is_cargo_host(&authority_host) {
                (
                    Some(Ecosystem::Cargo),
                    CodeIntent::Registry,
                    TrafficLane::CodeIntake,
                    "known Cargo package host".to_string(),
                    95,
                    true,
                    Some("cargo".to_string()),
                )
            } else if is_go_host(&authority_host) {
                (
                    Some(Ecosystem::Go),
                    CodeIntent::Registry,
                    TrafficLane::CodeIntake,
                    "known Go module host".to_string(),
                    90,
                    true,
                    Some("go".to_string()),
                )
            } else if is_oci_host(&authority_host) {
                (
                    Some(Ecosystem::Oci),
                    CodeIntent::OciPull,
                    TrafficLane::CodeIntake,
                    "known OCI registry host".to_string(),
                    90,
                    true,
                    Some("oci".to_string()),
                )
            } else if is_release_archive_path(&path) && is_codeish_host(&authority_host) {
                (
                    Some(Ecosystem::Archive),
                    CodeIntent::ReleaseArchive,
                    TrafficLane::CodeIntake,
                    "release archive path on code host".to_string(),
                    85,
                    true,
                    Some(authority_host.clone()),
                )
            } else if is_source_archive_path(&path) {
                (
                    Some(Ecosystem::Archive),
                    CodeIntent::SourceArchive,
                    TrafficLane::CodeIntake,
                    "source archive path detected".to_string(),
                    75,
                    true,
                    Some(authority_host.clone()),
                )
            } else if looks_like_install_script(&path, &user_agent) {
                (
                    Some(Ecosystem::Archive),
                    CodeIntent::InstallScript,
                    TrafficLane::CodeIntake,
                    "installer script pattern detected".to_string(),
                    70,
                    true,
                    Some(authority_host.clone()),
                )
            } else if is_codeish_host(&authority_host) {
                (
                    Some(Ecosystem::GenericWeb),
                    CodeIntent::UnknownCodeHost,
                    TrafficLane::CodeIntake,
                    "generic code-adjacent host".to_string(),
                    65,
                    true,
                    Some(authority_host.clone()),
                )
            } else {
                (
                    None,
                    CodeIntent::Browsing,
                    TrafficLane::Browse,
                    "ordinary browsing destination".to_string(),
                    40,
                    false,
                    Some(authority_host.clone()),
                )
            };

        Classification {
            lane,
            ecosystem,
            intent,
            reason,
            confidence,
            requires_quarantine,
            host_family,
        }
    }
}

fn normalize_authority(authority: &str) -> String {
    authority
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|ch| ch.is_ascii_digit()))
        .map(|(host, _)| host.trim_matches('[').trim_matches(']').to_string())
        .unwrap_or_else(|| authority.to_string())
        .trim_end_matches('.')
        .to_string()
}

fn has_suffix(authority: &str, suffixes: &[&str]) -> bool {
    suffixes
        .iter()
        .any(|suffix| authority == *suffix || authority.ends_with(&format!(".{suffix}")))
}

fn is_git_host(authority: &str) -> bool {
    has_suffix(
        authority,
        &[
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "sourcehut.org",
            "codeberg.org",
        ],
    )
}

fn is_npm_host(authority: &str) -> bool {
    has_suffix(authority, &["registry.npmjs.org", "npmjs.com"])
}

fn is_pypi_host(authority: &str) -> bool {
    has_suffix(authority, &["pypi.org", "files.pythonhosted.org"])
}

fn is_cargo_host(authority: &str) -> bool {
    has_suffix(
        authority,
        &["crates.io", "index.crates.io", "static.crates.io"],
    )
}

fn is_go_host(authority: &str) -> bool {
    has_suffix(authority, &["proxy.golang.org", "sum.golang.org", "go.dev"])
}

fn is_oci_host(authority: &str) -> bool {
    has_suffix(
        authority,
        &["ghcr.io", "docker.io", "registry-1.docker.io", "quay.io"],
    )
}

fn is_codeish_host(authority: &str) -> bool {
    is_git_host(authority)
        || is_npm_host(authority)
        || is_pypi_host(authority)
        || is_cargo_host(authority)
        || is_go_host(authority)
        || is_oci_host(authority)
        || has_suffix(
            authority,
            &["raw.githubusercontent.com", "objects.githubusercontent.com"],
        )
}

fn is_release_archive_path(path: &str) -> bool {
    path.contains("/releases/download/")
        || path.ends_with(".crate")
        || path.ends_with(".whl")
        || path.ends_with(".nupkg")
}

fn is_source_archive_path(path: &str) -> bool {
    [
        ".tar.gz", ".tgz", ".tar", ".zip", ".tar.xz", ".gem", ".jar", ".whl", ".crate",
    ]
    .iter()
    .any(|ext| path.ends_with(ext))
        || path.ends_with(".git")
}

fn looks_like_install_script(path: &str, user_agent: &str) -> bool {
    (path.contains("install") || path.ends_with(".sh") || path.ends_with(".ps1"))
        && (user_agent.contains("curl") || user_agent.contains("wget") || user_agent.is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use uuid::Uuid;

    use super::RequestClassifier;
    use crate::types::{CodeIntent, RequestObservation, TrafficLane};

    fn obs(authority: &str, path: &str, ua: Option<&str>) -> RequestObservation {
        RequestObservation {
            request_id: Uuid::new_v4(),
            observed_at: Utc::now(),
            scheme: "https".to_string(),
            authority: authority.to_string(),
            path: path.to_string(),
            method: "GET".to_string(),
            user_agent: ua.map(str::to_string),
            headers: BTreeMap::new(),
            selector_hint: None,
        }
    }

    #[test]
    fn classifies_git_hosts_as_code_intake() {
        let result = RequestClassifier::classify(&obs("github.com", "/acme/lib.git", None));
        assert_eq!(result.lane, TrafficLane::CodeIntake);
        assert_eq!(result.intent, CodeIntent::GitRemote);
    }

    #[test]
    fn classifies_mixed_case_and_trailing_dot_git_hosts_as_code_intake() {
        let result = RequestClassifier::classify(&obs("GitHub.COM.:443", "/acme/lib.git", None));
        assert_eq!(result.lane, TrafficLane::CodeIntake);
        assert_eq!(result.intent, CodeIntent::GitRemote);
        assert_eq!(result.host_family.as_deref(), Some("github.com"));
    }

    #[test]
    fn classifies_connect_authority_with_port_as_code_intake() {
        let result = RequestClassifier::classify(&obs("github.com:443", "", None));
        assert_eq!(result.lane, TrafficLane::CodeIntake);
        assert_eq!(result.intent, CodeIntent::GitRemote);
    }

    #[test]
    fn classifies_ipv6_authorities_without_false_positive() {
        let result = RequestClassifier::classify(&obs("[2001:db8::1]:443", "/docs", None));
        assert_eq!(result.lane, TrafficLane::Browse);
        assert_eq!(result.intent, CodeIntent::Browsing);
    }

    #[test]
    fn classifies_release_archives_as_code_intake() {
        let result = RequestClassifier::classify(&obs(
            "objects.githubusercontent.com",
            "/releases/download/v1.0.0/app.tar.gz",
            None,
        ));
        assert_eq!(result.lane, TrafficLane::CodeIntake);
        assert_eq!(result.intent, CodeIntent::ReleaseArchive);
    }

    #[test]
    fn classifies_install_script_paths_as_code_intake() {
        let result = RequestClassifier::classify(&obs(
            "example.com",
            "/bootstrap/install.sh",
            Some("curl/8.0"),
        ));
        assert_eq!(result.lane, TrafficLane::CodeIntake);
        assert_eq!(result.intent, CodeIntent::InstallScript);
    }

    #[test]
    fn leaves_normal_browsing_in_browse_lane() {
        let result =
            RequestClassifier::classify(&obs("docs.rs", "/axum/latest/axum/", Some("Mozilla/5.0")));
        assert_eq!(result.lane, TrafficLane::Browse);
        assert_eq!(result.intent, CodeIntent::Browsing);
    }
}
