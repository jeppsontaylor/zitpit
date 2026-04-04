use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EgressOutcome {
    Allow,
    Redact,
    Quarantine,
    Deny,
    StepUp,
    Unsupported,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PayloadClass {
    Credentials,
    PrivateKeyMaterial,
    ApiToken,
    BrowserSession,
    RegulatedPhi,
    RegulatedPii,
    SourceCode,
    InternalTopology,
    InfrastructureState,
    ModelAgentInternal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DestinationTrustZone {
    ZitpitInternal,
    ApprovedVcs,
    ApprovedRegistry,
    ApprovedModelApi,
    ApprovedDocs,
    UnknownExternal,
    BlockedExternal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentEncoding {
    Plaintext,
    Gzip,
    Zstd,
    Zip,
    Tar,
    Unknown,
    Encrypted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferKind {
    HttpReq,
    HttpRes,
    GitPush,
    GitFetch,
    ReleaseUpload,
    BrowserUpload,
    RawTcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlpMatch {
    pub detector_id: String,
    pub class: PayloadClass,
    pub index_start: usize,
    pub index_end: usize,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlpVerdict {
    pub is_clean: bool,
    pub matches: Vec<DlpMatch>,
    pub analyzed_bytes: usize,
    pub archive_unpacked: bool,
    pub encoding: ContentEncoding,
    pub payload_sha256: String,
    pub inspection_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressRequest {
    pub request_id: Uuid,
    pub session_id: Option<Uuid>,
    pub transfer_kind: TransferKind,
    pub destination_zone: DestinationTrustZone,
    pub target_url: Option<String>,
    pub encoding: ContentEncoding,
    pub payload_size: Option<usize>,
    pub verdict: DlpVerdict,
    #[serde(default)]
    pub regulated_transport_approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressDecision {
    pub outcome: EgressOutcome,
    pub reason: String,
    pub matched_classes: Vec<PayloadClass>,
    pub matched_detector_ids: Vec<String>,
    pub evidence_id: Uuid,
    pub policy_revision: String,
    pub content_encoding: ContentEncoding,
    pub archive_unpacked: bool,
    pub analyzed_bytes: usize,
    pub payload_sha256: String,
}

pub fn evaluate_egress(request: &EgressRequest) -> EgressDecision {
    evaluate_egress_with_mode(request, crate::types::LockdownMode::Protected)
}

pub fn evaluate_egress_with_mode(request: &EgressRequest, mode: crate::types::LockdownMode) -> EgressDecision {
    let matched_classes = request
        .verdict
        .matches
        .iter()
        .map(|m| m.class)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let matched_detector_ids = request
        .verdict
        .matches
        .iter()
        .map(|m| m.detector_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let (mut outcome, mut reason) = if mode.is_break_glass() {
        (
            EgressOutcome::Allow,
            "break-glass mode overrides egress policy".to_string(),
        )
    } else if let Some(error) = &request.verdict.inspection_error {
        (
            EgressOutcome::Unsupported,
            format!("payload inspection failed closed: {error}"),
        )
    } else if matches!(
        request.destination_zone,
        DestinationTrustZone::BlockedExternal
    ) {
        (
            EgressOutcome::Deny,
            "destination is explicitly blocked".to_string(),
        )
    } else if request.destination_zone == DestinationTrustZone::UnknownExternal {
        if matched_classes.is_empty() {
            if mode.egress_default_deny() {
                (
                    EgressOutcome::Deny,
                    "default deny for unknown external destinations".to_string(),
                )
            } else {
                (
                    EgressOutcome::Allow,
                    "relaxed mode allows clean egress to unknown destinations".to_string(),
                )
            }
        } else {
            (
                EgressOutcome::Deny,
                "blocked sensitive payload to an unknown external destination".to_string(),
            )
        }
    } else {
        decide_sensitive_payloads(request, &matched_classes)
    };

    if mode.stepup_treated_as_deny() && outcome == EgressOutcome::StepUp {
        outcome = EgressOutcome::Deny;
        reason = format!("{} (downgraded by sealed mode)", reason);
    }

    EgressDecision {
        outcome,
        reason,
        matched_classes,
        matched_detector_ids,
        evidence_id: Uuid::new_v4(),
        policy_revision: "max-containment-dlp-v2".to_string(),
        content_encoding: request.encoding,
        archive_unpacked: request.verdict.archive_unpacked,
        analyzed_bytes: request.verdict.analyzed_bytes,
        payload_sha256: request.verdict.payload_sha256.clone(),
    }
}

fn decide_sensitive_payloads(
    request: &EgressRequest,
    matched_classes: &[PayloadClass],
) -> (EgressOutcome, String) {
    if matched_classes.is_empty() {
        return (EgressOutcome::Allow, "egress permitted".to_string());
    }

    for class in matched_classes {
        match class {
            PayloadClass::PrivateKeyMaterial => {
                return (
                    EgressOutcome::Deny,
                    "blocked private key material before transmission".to_string(),
                );
            }
            PayloadClass::BrowserSession => {
                return (
                    EgressOutcome::Deny,
                    "blocked browser session material before transmission".to_string(),
                );
            }
            PayloadClass::ApiToken | PayloadClass::Credentials => {
                return (
                    EgressOutcome::Deny,
                    "blocked reusable credential material before transmission".to_string(),
                );
            }
            PayloadClass::RegulatedPhi => {
                if request.regulated_transport_approved {
                    return (
                        EgressOutcome::StepUp,
                        "regulated PHI requires an explicit regulated transport policy".to_string(),
                    );
                }
                return (
                    EgressOutcome::Deny,
                    "blocked regulated PHI before transmission".to_string(),
                );
            }
            PayloadClass::RegulatedPii => {
                return (
                    EgressOutcome::Deny,
                    "blocked regulated PII before transmission".to_string(),
                );
            }
            PayloadClass::SourceCode
            | PayloadClass::InternalTopology
            | PayloadClass::InfrastructureState
            | PayloadClass::ModelAgentInternal => {
                if request.destination_zone == DestinationTrustZone::ApprovedModelApi {
                    return (
                        EgressOutcome::StepUp,
                        "sensitive source or model context requires step-up before model upload"
                            .to_string(),
                    );
                }
                if request.destination_zone != DestinationTrustZone::ZitpitInternal
                    && request.destination_zone != DestinationTrustZone::ApprovedVcs
                {
                    return (
                        EgressOutcome::Deny,
                        "blocked source or internal context before transmission".to_string(),
                    );
                }
            }
        }
    }

    (EgressOutcome::Allow, "egress permitted".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_request(zone: DestinationTrustZone) -> EgressRequest {
        EgressRequest {
            request_id: Uuid::new_v4(),
            session_id: None,
            transfer_kind: TransferKind::HttpReq,
            destination_zone: zone,
            target_url: Some("https://example.test/upload".to_string()),
            encoding: ContentEncoding::Plaintext,
            payload_size: Some(12),
            verdict: DlpVerdict {
                is_clean: true,
                matches: vec![],
                analyzed_bytes: 12,
                archive_unpacked: false,
                encoding: ContentEncoding::Plaintext,
                payload_sha256: "abc".to_string(),
                inspection_error: None,
            },
            regulated_transport_approved: false,
        }
    }

    #[test]
    fn denies_unknown_destination_even_when_payload_is_clean() {
        let decision = evaluate_egress(&clean_request(DestinationTrustZone::UnknownExternal));
        assert_eq!(decision.outcome, EgressOutcome::Deny);
    }

    #[test]
    fn allows_clean_internal_destination() {
        let decision = evaluate_egress(&clean_request(DestinationTrustZone::ZitpitInternal));
        assert_eq!(decision.outcome, EgressOutcome::Allow);
    }

    #[test]
    fn fails_closed_when_inspection_errors() {
        let mut request = clean_request(DestinationTrustZone::ZitpitInternal);
        request.verdict.inspection_error = Some("encrypted zip entry".to_string());
        request.encoding = ContentEncoding::Encrypted;
        let decision = evaluate_egress(&request);
        assert_eq!(decision.outcome, EgressOutcome::Unsupported);
    }

    #[test]
    fn egress_evaluator_handles_regulated_override() {
        let mut request = egress_req(
            DestinationTrustZone::ZitpitInternal,
            PayloadClass::RegulatedData,
        );
        let decision = evaluate_egress(&request);
        assert_eq!(decision.outcome, EgressOutcome::Deny);

        request.regulated_transport_approved = true;
        let decision = evaluate_egress(&request);
        assert_eq!(decision.outcome, EgressOutcome::Allow);
    }

    #[test]
    fn sealed_mode_denies_stepup_as_deny() {
        let request = egress_req(
            DestinationTrustZone::ApprovedRegistry,
            PayloadClass::Credentials,
        );
        let decision = evaluate_egress_with_mode(&request, crate::types::LockdownMode::Sealed);
        assert_eq!(decision.outcome, EgressOutcome::Deny);
        assert!(decision.reason.contains("downgraded by sealed mode"));
    }

    #[test]
    fn relaxed_mode_allows_unknown_clean_egress() {
        let request = egress_req(
            DestinationTrustZone::UnknownExternal,
            PayloadClass::InfrastructureState,
        );
        let mut clean_request = request;
        clean_request.verdict.matches.clear();
        
        let decision = evaluate_egress_with_mode(&clean_request, crate::types::LockdownMode::Relaxed);
        assert_eq!(decision.outcome, EgressOutcome::Allow);
        assert!(decision.reason.contains("relaxed mode allows clean egress"));
    }

    #[test]
    fn break_glass_mode_allows_all_egress_with_audit() {
        let request = egress_req(
            DestinationTrustZone::BlockedExternal,
            PayloadClass::Credentials,
        );
        let decision = evaluate_egress_with_mode(&request, crate::types::LockdownMode::BreakGlass);
        assert_eq!(decision.outcome, EgressOutcome::Allow);
        assert!(decision.reason.contains("break-glass mode overrides egress policy"));
    }
}
