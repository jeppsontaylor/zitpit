use chrono::Utc;
use semver::{Version, VersionReq};

use crate::{
    classifier::RequestClassifier,
    manifest::ManifestCatalog,
    types::{
        ApprovalStatus, ArtifactCoordinate, Classification, DecisionRequest, FallbackTarget,
        PolicyConfig, ProxyAction, ProxyDecision, RequestObservation, SelectorKind, TrafficLane,
    },
};

#[derive(Debug, Clone)]
pub struct DecisionEngine {
    pub policy: PolicyConfig,
}

impl DecisionEngine {
    pub fn new(policy: PolicyConfig) -> Self {
        Self { policy }
    }

    pub fn classify(&self, observation: &RequestObservation) -> Classification {
        RequestClassifier::classify(observation)
    }

    pub fn decide(&self, request: &DecisionRequest, catalog: &ManifestCatalog) -> ProxyDecision {
        let classification = self.classify(&request.observation);

        if classification.lane == TrafficLane::Browse {
            if !self.policy.allow_browse_lane {
                return ProxyDecision {
                    action: ProxyAction::Blocked,
                    reason: "browse traffic is disabled by policy".to_string(),
                    classification,
                    manifest_status: None,
                    fallback: None,
                    hold_until: None,
                    matched_record: None,
                    audit_tags: vec![
                        "lane:browse".to_string(),
                        "policy:browse_disabled".to_string(),
                    ],
                };
            }
            return ProxyDecision {
                action: ProxyAction::Allow,
                reason: "browse traffic allowed and logged".to_string(),
                classification,
                manifest_status: None,
                fallback: None,
                hold_until: None,
                matched_record: None,
                audit_tags: vec!["lane:browse".to_string(), "log:https".to_string()],
            };
        }

        if let Some(ecosystem) = classification.ecosystem {
            if !self.policy.enabled_ecosystems.contains(&ecosystem) {
                return ProxyDecision {
                    action: ProxyAction::Blocked,
                    reason: format!("ecosystem {ecosystem:?} is disabled by policy"),
                    classification,
                    manifest_status: None,
                    fallback: None,
                    hold_until: None,
                    matched_record: None,
                    audit_tags: vec![
                        "lane:code".to_string(),
                        "policy:ecosystem_disabled".to_string(),
                    ],
                };
            }
        }

        let coordinate = request
            .coordinate
            .clone()
            .unwrap_or_else(|| infer_coordinate(&request.observation, &classification));

        let exact_match = catalog.find_exact(&coordinate);
        if let Some(record) = exact_match {
            match record.status {
                ApprovalStatus::Approved => {
                    return ProxyDecision {
                        action: ProxyAction::Allow,
                        reason: "exact requested selector is approved".to_string(),
                        classification,
                        manifest_status: Some(record.status),
                        fallback: None,
                        hold_until: None,
                        matched_record: Some(record.clone()),
                        audit_tags: vec![
                            "lane:code".to_string(),
                            "manifest:exact_hit".to_string(),
                            "decision:allow".to_string(),
                        ],
                    };
                }
                ApprovalStatus::Pending => {
                    let fallback = if coordinate.selector_kind.is_exact() {
                        record.fallback.clone()
                    } else {
                        record
                            .fallback
                            .clone()
                            .or_else(|| catalog.latest_approved_fallback(&coordinate))
                    };

                    return self.pending_or_fallback(
                        classification,
                        record.hold_until,
                        record.clone(),
                        fallback,
                        coordinate.selector_kind,
                        "requested selector is pending detonation or hold window",
                    );
                }
                ApprovalStatus::Blocked | ApprovalStatus::Revoked => {
                    let fallback = if coordinate.selector_kind.is_exact() {
                        record.fallback.clone()
                    } else {
                        record
                            .fallback
                            .clone()
                            .or_else(|| catalog.latest_approved_fallback(&coordinate))
                    };

                    return self.block_or_fallback(
                        classification,
                        record.clone(),
                        fallback,
                        coordinate.selector_kind,
                        "requested selector is blocked or revoked",
                    );
                }
            }
        }

        if coordinate.selector_kind.is_exact() {
            return ProxyDecision {
                action: ProxyAction::Pending,
                reason: "exact selector is unknown and must fail closed".to_string(),
                classification,
                manifest_status: None,
                fallback: None,
                hold_until: Some(
                    Utc::now() + chrono::TimeDelta::hours(self.policy.hold_duration_hours),
                ),
                matched_record: None,
                audit_tags: vec![
                    "lane:code".to_string(),
                    "manifest:miss".to_string(),
                    "decision:pending".to_string(),
                ],
            };
        }

        if let Some(fallback) = catalog.latest_approved_fallback(&coordinate) {
            return ProxyDecision {
                action: ProxyAction::Fallback,
                reason:
                    "requested floating selector is not approved yet; serving latest approved match"
                        .to_string(),
                classification,
                manifest_status: Some(ApprovalStatus::Approved),
                fallback: Some(fallback),
                hold_until: None,
                matched_record: catalog.latest_approved_match(&coordinate).cloned(),
                audit_tags: vec![
                    "lane:code".to_string(),
                    "manifest:fallback".to_string(),
                    "decision:fallback".to_string(),
                ],
            };
        }

        ProxyDecision {
            action: ProxyAction::Pending,
            reason: "unknown floating selector has no approved fallback yet".to_string(),
            classification,
            manifest_status: None,
            fallback: None,
            hold_until: Some(
                Utc::now() + chrono::TimeDelta::hours(self.policy.hold_duration_hours),
            ),
            matched_record: None,
            audit_tags: vec![
                "lane:code".to_string(),
                "manifest:miss".to_string(),
                "decision:pending".to_string(),
            ],
        }
    }

    fn pending_or_fallback(
        &self,
        classification: Classification,
        hold_until: Option<chrono::DateTime<Utc>>,
        record: crate::types::ManifestRecord,
        fallback: Option<FallbackTarget>,
        selector_kind: SelectorKind,
        reason: &str,
    ) -> ProxyDecision {
        if selector_kind.is_exact() || fallback.is_none() {
            ProxyDecision {
                action: ProxyAction::Pending,
                reason: reason.to_string(),
                classification,
                manifest_status: Some(ApprovalStatus::Pending),
                fallback,
                hold_until,
                matched_record: Some(record),
                audit_tags: vec![
                    "lane:code".to_string(),
                    "manifest:pending".to_string(),
                    "decision:pending".to_string(),
                ],
            }
        } else {
            ProxyDecision {
                action: ProxyAction::Fallback,
                reason: format!("{reason}; fallback is available for floating selector"),
                classification,
                manifest_status: Some(ApprovalStatus::Pending),
                fallback,
                hold_until,
                matched_record: Some(record),
                audit_tags: vec![
                    "lane:code".to_string(),
                    "manifest:pending".to_string(),
                    "decision:fallback".to_string(),
                ],
            }
        }
    }

    fn block_or_fallback(
        &self,
        classification: Classification,
        record: crate::types::ManifestRecord,
        fallback: Option<FallbackTarget>,
        selector_kind: SelectorKind,
        reason: &str,
    ) -> ProxyDecision {
        if selector_kind.is_exact() || fallback.is_none() {
            ProxyDecision {
                action: ProxyAction::Blocked,
                reason: reason.to_string(),
                classification,
                manifest_status: Some(record.status),
                fallback,
                hold_until: record.hold_until,
                matched_record: Some(record),
                audit_tags: vec![
                    "lane:code".to_string(),
                    "manifest:block".to_string(),
                    "decision:blocked".to_string(),
                ],
            }
        } else {
            ProxyDecision {
                action: ProxyAction::Fallback,
                reason: format!("{reason}; floating selector downgraded to approved fallback"),
                classification,
                manifest_status: Some(record.status),
                fallback,
                hold_until: record.hold_until,
                matched_record: Some(record),
                audit_tags: vec![
                    "lane:code".to_string(),
                    "manifest:block".to_string(),
                    "decision:fallback".to_string(),
                ],
            }
        }
    }
}

fn infer_coordinate(
    observation: &RequestObservation,
    classification: &Classification,
) -> ArtifactCoordinate {
    let ecosystem = classification
        .ecosystem
        .unwrap_or(crate::types::Ecosystem::Archive);
    let selector_hint = observation.selector_hint.clone();
    ArtifactCoordinate {
        ecosystem,
        source: format!(
            "{}://{}{}",
            observation.scheme, observation.authority, observation.path
        ),
        requested_selector: selector_hint
            .as_ref()
            .map(|hint| hint.requested.clone())
            .unwrap_or_else(|| "__unspecified__".to_string()),
        selector_kind: selector_hint
            .map(|hint| hint.kind)
            .unwrap_or(SelectorKind::Unspecified),
    }
}

pub fn detect_ref_drift(
    existing: &crate::types::ManifestRecord,
    incoming_resolved_target: &str,
    incoming_normalized_digest: &str,
) -> bool {
    existing.resolved_target != incoming_resolved_target
        || existing.normalized_digest_sha256 != incoming_normalized_digest
}

pub fn semver_fallback_matches(range: &str, version: &str) -> bool {
    VersionReq::parse(range)
        .ok()
        .zip(Version::parse(version).ok())
        .map(|(req, version)| req.matches(&version))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use crate::{
        manifest::ManifestCatalog,
        types::{
            ApprovalStatus, ArtifactCoordinate, DecisionRequest, Ecosystem, ProxyAction,
            RequestObservation, SelectorHint, SelectorKind,
        },
    };
    use chrono::{TimeDelta, Utc};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    use super::{DecisionEngine, detect_ref_drift, semver_fallback_matches};

    fn sample_catalog() -> ManifestCatalog {
        ManifestCatalog::sample()
    }

    fn obs(selector: SelectorHint) -> RequestObservation {
        RequestObservation {
            request_id: Uuid::new_v4(),
            observed_at: Utc::now(),
            scheme: "https".to_string(),
            authority: "registry.npmjs.org".to_string(),
            path: "/lodash".to_string(),
            method: "GET".to_string(),
            user_agent: Some("npm/10".to_string()),
            headers: BTreeMap::new(),
            selector_hint: Some(selector),
        }
    }

    #[test]
    fn exact_unknown_selector_fails_closed() {
        let engine = DecisionEngine::new(Default::default());
        let decision = engine.decide(
            &DecisionRequest {
                observation: obs(SelectorHint {
                    requested: "99.99.99".to_string(),
                    kind: SelectorKind::ExactVersion,
                }),
                coordinate: Some(ArtifactCoordinate {
                    ecosystem: Ecosystem::Npm,
                    source: "npm:lodash".to_string(),
                    requested_selector: "99.99.99".to_string(),
                    selector_kind: SelectorKind::ExactVersion,
                }),
            },
            &sample_catalog(),
        );
        assert_eq!(decision.action, ProxyAction::Pending);
        assert!(decision.reason.contains("fail closed"));
    }

    #[test]
    fn approved_exact_selector_allows() {
        let engine = DecisionEngine::new(Default::default());
        let decision = engine.decide(
            &DecisionRequest {
                observation: obs(SelectorHint {
                    requested: "4.17.21".to_string(),
                    kind: SelectorKind::ExactVersion,
                }),
                coordinate: Some(ArtifactCoordinate {
                    ecosystem: Ecosystem::Npm,
                    source: "npm:lodash".to_string(),
                    requested_selector: "4.17.21".to_string(),
                    selector_kind: SelectorKind::ExactVersion,
                }),
            },
            &sample_catalog(),
        );
        assert_eq!(decision.action, ProxyAction::Allow);
        assert_eq!(decision.manifest_status, Some(ApprovalStatus::Approved));
    }

    #[test]
    fn floating_pending_version_falls_back_to_latest_approved() {
        let engine = DecisionEngine::new(Default::default());
        let decision = engine.decide(
            &DecisionRequest {
                observation: obs(SelectorHint {
                    requested: "^4.17".to_string(),
                    kind: SelectorKind::SemverRange,
                }),
                coordinate: Some(ArtifactCoordinate {
                    ecosystem: Ecosystem::Npm,
                    source: "npm:lodash".to_string(),
                    requested_selector: "^4.17".to_string(),
                    selector_kind: SelectorKind::SemverRange,
                }),
            },
            &sample_catalog(),
        );
        assert_eq!(decision.action, ProxyAction::Fallback);
        assert_eq!(
            decision
                .fallback
                .as_ref()
                .expect("fallback should exist")
                .selector,
            "4.17.21"
        );
    }

    #[test]
    fn blocked_exact_record_stays_blocked() {
        let engine = DecisionEngine::new(Default::default());
        let catalog = ManifestCatalog::new(vec![crate::ManifestRecord {
            ecosystem: Ecosystem::Archive,
            source: "https://github.com/acme/tool/releases/download/v2.0.0/tool.tar.gz".to_string(),
            requested_selector: "v2.0.0".to_string(),
            selector_kind: SelectorKind::ExactVersion,
            resolved_target: "tool-2.0.0".to_string(),
            raw_digest_sha256: crate::manifest::digest_for("blocked-raw"),
            normalized_digest_sha256: crate::manifest::digest_for("blocked-tree"),
            content_digest_sha256: None,
            normalized_content_digest_sha256: None,
            status: ApprovalStatus::Blocked,
            first_seen_at: Utc::now(),
            hold_until: Some(Utc::now() + TimeDelta::days(14)),
            approved_at: None,
            fallback: Some(crate::types::FallbackTarget {
                selector: "v1.9.4".to_string(),
                resolved_target: Some("tool-1.9.4".to_string()),
                reason: "blocked sample".to_string(),
            }),
            detector_refs: vec!["report://archive/tool/v2.0.0".to_string()],
            metadata: BTreeMap::new(),
        }]);
        let decision = engine.decide(
            &DecisionRequest {
                observation: RequestObservation {
                    request_id: Uuid::new_v4(),
                    observed_at: Utc::now(),
                    scheme: "https".to_string(),
                    authority: "github.com".to_string(),
                    path: "/acme/tool/releases/download/v2.0.0/tool.tar.gz".to_string(),
                    method: "GET".to_string(),
                    user_agent: Some("curl/8.0".to_string()),
                    headers: BTreeMap::new(),
                    selector_hint: Some(SelectorHint {
                        requested: "v2.0.0".to_string(),
                        kind: SelectorKind::ExactVersion,
                    }),
                },
                coordinate: Some(ArtifactCoordinate {
                    ecosystem: Ecosystem::Archive,
                    source: "https://github.com/acme/tool/releases/download/v2.0.0/tool.tar.gz"
                        .to_string(),
                    requested_selector: "v2.0.0".to_string(),
                    selector_kind: SelectorKind::ExactVersion,
                }),
            },
            &catalog,
        );
        assert_eq!(decision.action, ProxyAction::Blocked);
        assert_eq!(decision.manifest_status, Some(ApprovalStatus::Blocked));
    }

    #[test]
    fn detects_tag_drift() {
        let catalog = sample_catalog();
        let existing = catalog
            .records
            .iter()
            .find(|record| {
                record.ecosystem == Ecosystem::Git
                    && record.requested_selector == "refs/tags/v1.2.3"
                    && record.status == ApprovalStatus::Approved
            })
            .expect("tag fixture should exist");
        assert!(detect_ref_drift(
            existing,
            "fedcba9876543210fedcba9876543210fedcba98",
            "deadbeef"
        ));
    }

    #[test]
    fn semver_matching_supports_fallback_selection() {
        assert!(semver_fallback_matches("^4.17", "4.17.21"));
        assert!(!semver_fallback_matches("^4.17", "5.0.0"));
    }

    #[test]
    fn pending_records_keep_hold_window() {
        let catalog = sample_catalog();
        let pending = catalog
            .records
            .iter()
            .find(|record| record.status == ApprovalStatus::Pending)
            .expect("pending record should exist");
        assert!(
            pending
                .hold_until
                .expect("hold window")
                .gt(&(Utc::now() - TimeDelta::hours(1)))
        );
    }
}
