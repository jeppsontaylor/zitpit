use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{TimeDelta, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::policy::semver_fallback_matches;
use crate::types::{
    ApprovalStatus, ArtifactCoordinate, Ecosystem, FallbackTarget, ManifestRecord, SelectorKind,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestRoot {
    pub version: u64,
    pub generated_at: chrono::DateTime<Utc>,
    pub public_key_base64: String,
    pub shards: Vec<ManifestShardRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestShardRef {
    pub ecosystem: Ecosystem,
    pub shard: String,
    pub record_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestShard {
    pub ecosystem: Ecosystem,
    pub shard: String,
    pub version: u64,
    pub generated_at: chrono::DateTime<Utc>,
    pub records: Vec<ManifestRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEnvelope<T> {
    pub key_id: String,
    pub payload: T,
    pub payload_json: String,
    pub signature_base64: String,
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("failed to serialize payload: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("signature decode failed: {0}")]
    SignatureDecode(#[from] base64::DecodeError),
    #[error("signature verification failed")]
    Verification,
}

#[derive(Debug, Clone)]
pub struct ManifestSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl ManifestSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn key_id(&self) -> String {
        hex::encode(self.verifying_key.as_bytes())
    }

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.verifying_key.as_bytes())
    }

    pub fn sign<T>(&self, payload: &T) -> Result<SignedEnvelope<T>, ManifestError>
    where
        T: Serialize + Clone,
    {
        let payload_json = serde_json::to_string_pretty(payload)?;
        let signature = self.signing_key.sign(payload_json.as_bytes());
        Ok(SignedEnvelope {
            key_id: self.key_id(),
            payload: payload.clone(),
            payload_json,
            signature_base64: STANDARD.encode(signature.to_bytes()),
        })
    }

    pub fn verify<T>(&self, envelope: &SignedEnvelope<T>) -> Result<T, ManifestError>
    where
        T: Serialize + DeserializeOwned + Clone,
    {
        let signature_bytes = STANDARD.decode(&envelope.signature_base64)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| ManifestError::Verification)?;
        self.verifying_key
            .verify(envelope.payload_json.as_bytes(), &signature)
            .map_err(|_| ManifestError::Verification)?;
        serde_json::from_str(&envelope.payload_json).map_err(ManifestError::Serialize)
    }
}

#[derive(Debug, Clone)]
pub struct ManifestCatalog {
    pub records: Vec<ManifestRecord>,
}

impl ManifestCatalog {
    pub fn new(records: Vec<ManifestRecord>) -> Self {
        Self { records }
    }

    pub fn sample() -> Self {
        let now = Utc::now();
        let records = vec![
            ManifestRecord {
                ecosystem: Ecosystem::Git,
                source: "https://github.com/acme/approved-repo.git".to_string(),
                requested_selector: "refs/heads/main".to_string(),
                selector_kind: SelectorKind::Branch,
                resolved_target: "1f2e3d4c5b6a7980112233445566778899aabbcc".to_string(),
                raw_digest_sha256: digest_for("git-main-raw"),
                normalized_digest_sha256: digest_for("git-main-tree"),
                status: ApprovalStatus::Approved,
                first_seen_at: now - TimeDelta::days(30),
                hold_until: None,
                approved_at: Some(now - TimeDelta::days(29)),
                fallback: None,
                detector_refs: vec!["report://approved-repo/main".to_string()],
                metadata: BTreeMap::from([("tree_id".to_string(), "tree-main-001".to_string())]),
            },
            ManifestRecord {
                ecosystem: Ecosystem::Git,
                source: "https://github.com/acme/approved-repo.git".to_string(),
                requested_selector: "refs/tags/v1.2.3".to_string(),
                selector_kind: SelectorKind::Tag,
                resolved_target: "abc1234567890abc1234567890abc1234567890".to_string(),
                raw_digest_sha256: digest_for("git-tag-raw"),
                normalized_digest_sha256: digest_for("git-tag-tree"),
                status: ApprovalStatus::Approved,
                first_seen_at: now - TimeDelta::days(20),
                hold_until: None,
                approved_at: Some(now - TimeDelta::days(19)),
                fallback: None,
                detector_refs: vec!["report://approved-repo/v1.2.3".to_string()],
                metadata: BTreeMap::from([("tree_id".to_string(), "tree-tag-123".to_string())]),
            },
            ManifestRecord {
                ecosystem: Ecosystem::Npm,
                source: "npm:lodash".to_string(),
                requested_selector: "4.17.21".to_string(),
                selector_kind: SelectorKind::ExactVersion,
                resolved_target: "lodash@4.17.21".to_string(),
                raw_digest_sha256: digest_for("npm-lodash-4.17.21-raw"),
                normalized_digest_sha256: digest_for("npm-lodash-4.17.21-tree"),
                status: ApprovalStatus::Approved,
                first_seen_at: now - TimeDelta::days(120),
                hold_until: None,
                approved_at: Some(now - TimeDelta::days(119)),
                fallback: None,
                detector_refs: vec!["report://npm/lodash/4.17.21".to_string()],
                metadata: BTreeMap::new(),
            },
            ManifestRecord {
                ecosystem: Ecosystem::Npm,
                source: "npm:lodash".to_string(),
                requested_selector: "4.17.22".to_string(),
                selector_kind: SelectorKind::ExactVersion,
                resolved_target: "lodash@4.17.22".to_string(),
                raw_digest_sha256: digest_for("npm-lodash-4.17.22-raw"),
                normalized_digest_sha256: digest_for("npm-lodash-4.17.22-tree"),
                status: ApprovalStatus::Pending,
                first_seen_at: now - TimeDelta::hours(12),
                hold_until: Some(now + TimeDelta::days(13)),
                approved_at: None,
                fallback: Some(FallbackTarget {
                    selector: "4.17.21".to_string(),
                    resolved_target: Some("lodash@4.17.21".to_string()),
                    reason: "latest approved version remains 4.17.21 during hold window"
                        .to_string(),
                }),
                detector_refs: vec!["report://npm/lodash/4.17.22".to_string()],
                metadata: BTreeMap::new(),
            },
            ManifestRecord {
                ecosystem: Ecosystem::Pypi,
                source: "pypi:requests".to_string(),
                requested_selector: "2.32.4".to_string(),
                selector_kind: SelectorKind::ExactVersion,
                resolved_target: "requests==2.32.4".to_string(),
                raw_digest_sha256: digest_for("pypi-requests-2.32.4-raw"),
                normalized_digest_sha256: digest_for("pypi-requests-2.32.4-tree"),
                status: ApprovalStatus::Approved,
                first_seen_at: now - TimeDelta::days(30),
                hold_until: None,
                approved_at: Some(now - TimeDelta::days(29)),
                fallback: None,
                detector_refs: vec!["report://pypi/requests/2.32.4".to_string()],
                metadata: BTreeMap::new(),
            },
            ManifestRecord {
                ecosystem: Ecosystem::Cargo,
                source: "cargo:serde".to_string(),
                requested_selector: "1.0.228".to_string(),
                selector_kind: SelectorKind::ExactVersion,
                resolved_target: "serde@1.0.228".to_string(),
                raw_digest_sha256: digest_for("cargo-serde-1.0.228-raw"),
                normalized_digest_sha256: digest_for("cargo-serde-1.0.228-tree"),
                status: ApprovalStatus::Approved,
                first_seen_at: now - TimeDelta::days(10),
                hold_until: None,
                approved_at: Some(now - TimeDelta::days(9)),
                fallback: None,
                detector_refs: vec!["report://cargo/serde/1.0.228".to_string()],
                metadata: BTreeMap::new(),
            },
            ManifestRecord {
                ecosystem: Ecosystem::Go,
                source: "go:github.com/gin-gonic/gin".to_string(),
                requested_selector: "v1.10.0".to_string(),
                selector_kind: SelectorKind::ExactVersion,
                resolved_target: "github.com/gin-gonic/gin@v1.10.0".to_string(),
                raw_digest_sha256: digest_for("go-gin-1.10.0-raw"),
                normalized_digest_sha256: digest_for("go-gin-1.10.0-tree"),
                status: ApprovalStatus::Approved,
                first_seen_at: now - TimeDelta::days(8),
                hold_until: None,
                approved_at: Some(now - TimeDelta::days(7)),
                fallback: None,
                detector_refs: vec!["report://go/gin/v1.10.0".to_string()],
                metadata: BTreeMap::new(),
            },
            ManifestRecord {
                ecosystem: Ecosystem::Archive,
                source:
                    "https://github.com/acme/tool/releases/download/v2.0.0/tool-linux-amd64.tar.gz"
                        .to_string(),
                requested_selector: "v2.0.0".to_string(),
                selector_kind: SelectorKind::Tag,
                resolved_target: "tool-v2.0.0-archive".to_string(),
                raw_digest_sha256: digest_for("archive-tool-2.0.0-raw"),
                normalized_digest_sha256: digest_for("archive-tool-2.0.0-tree"),
                status: ApprovalStatus::Blocked,
                first_seen_at: now - TimeDelta::hours(3),
                hold_until: Some(now + TimeDelta::days(14)),
                approved_at: None,
                fallback: Some(FallbackTarget {
                    selector: "v1.9.4".to_string(),
                    resolved_target: Some("tool-v1.9.4-archive".to_string()),
                    reason: "v2.0.0 triggered downloader and shell-spawn tripwires".to_string(),
                }),
                detector_refs: vec!["report://archive/tool/v2.0.0".to_string()],
                metadata: BTreeMap::new(),
            },
        ];
        Self { records }
    }

    pub fn root(&self, signer: &ManifestSigner) -> ManifestRoot {
        let shards = self
            .approved_visible_records()
            .into_iter()
            .fold(
                BTreeMap::<(Ecosystem, String), usize>::new(),
                |mut acc, record| {
                    *acc.entry((record.ecosystem, shard_for(&record.source)))
                        .or_insert(0) += 1;
                    acc
                },
            )
            .into_iter()
            .map(|((ecosystem, shard), record_count)| ManifestShardRef {
                ecosystem,
                shard,
                record_count,
            })
            .collect();

        ManifestRoot {
            version: 1,
            generated_at: Utc::now(),
            public_key_base64: signer.public_key_base64(),
            shards,
        }
    }

    pub fn shard(&self, ecosystem: Ecosystem, shard: &str) -> ManifestShard {
        let records = self
            .approved_visible_records()
            .into_iter()
            .filter(|record| record.ecosystem == ecosystem && shard_for(&record.source) == shard)
            .collect::<Vec<_>>();
        ManifestShard {
            ecosystem,
            shard: shard.to_string(),
            version: 1,
            generated_at: Utc::now(),
            records,
        }
    }

    pub fn approved_visible_records(&self) -> Vec<ManifestRecord> {
        self.records
            .iter()
            .filter(|record| record.status == ApprovalStatus::Approved)
            .cloned()
            .collect()
    }

    pub fn shard_names(&self, ecosystem: Ecosystem) -> Vec<String> {
        let mut names = BTreeSet::new();
        for record in self.approved_visible_records() {
            if record.ecosystem == ecosystem {
                names.insert(shard_for(&record.source));
            }
        }
        names.into_iter().collect()
    }

    pub fn find_exact(&self, coordinate: &ArtifactCoordinate) -> Option<&ManifestRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.ecosystem == coordinate.ecosystem
                    && record.source == coordinate.source
                    && record.requested_selector == coordinate.requested_selector
            })
            .max_by_key(|record| {
                (
                    record.approved_at.unwrap_or(record.first_seen_at),
                    status_precedence(record.status),
                )
            })
    }

    pub fn latest_approved_match(
        &self,
        coordinate: &ArtifactCoordinate,
    ) -> Option<&ManifestRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.ecosystem == coordinate.ecosystem
                    && record.source == coordinate.source
                    && record.status == ApprovalStatus::Approved
            })
            .filter(|record| selector_matches(coordinate, record))
            .max_by_key(|record| record.approved_at.unwrap_or(record.first_seen_at))
    }

    pub fn latest_approved_fallback(
        &self,
        coordinate: &ArtifactCoordinate,
    ) -> Option<FallbackTarget> {
        self.latest_approved_match(coordinate)
            .map(|record| FallbackTarget {
                selector: record.requested_selector.clone(),
                resolved_target: Some(record.resolved_target.clone()),
                reason: "latest approved artifact that satisfies the floating selector".to_string(),
            })
    }

    pub fn approved_records_for_source(&self, source: &str) -> Vec<&ManifestRecord> {
        self.records
            .iter()
            .filter(|record| record.source == source && record.status == ApprovalStatus::Approved)
            .collect()
    }

    pub fn latest_approved_for_source(&self, source: &str) -> Option<&ManifestRecord> {
        self.records
            .iter()
            .filter(|record| record.source == source && record.status == ApprovalStatus::Approved)
            .max_by_key(|record| record.approved_at.unwrap_or(record.first_seen_at))
    }
}

fn selector_matches(coordinate: &ArtifactCoordinate, record: &ManifestRecord) -> bool {
    match coordinate.selector_kind {
        SelectorKind::SemverRange => {
            semver_fallback_matches(&coordinate.requested_selector, &record.requested_selector)
        }
        SelectorKind::Branch | SelectorKind::Tag => {
            record.requested_selector == coordinate.requested_selector
        }
        SelectorKind::Floating | SelectorKind::Url => true,
        SelectorKind::ExactVersion | SelectorKind::ExactCommit => {
            record.requested_selector == coordinate.requested_selector
        }
    }
}

fn status_precedence(status: ApprovalStatus) -> u8 {
    match status {
        ApprovalStatus::Approved => 4,
        ApprovalStatus::Blocked => 3,
        ApprovalStatus::Revoked => 2,
        ApprovalStatus::Pending => 1,
    }
}

pub fn digest_for(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn shard_for(source: &str) -> String {
    digest_for(source)[..2].to_string()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};

    use super::{ManifestCatalog, ManifestSigner, digest_for};
    use crate::types::{
        ApprovalStatus, ArtifactCoordinate, Ecosystem, ManifestRecord, SelectorKind,
    };

    #[test]
    fn signed_manifest_verifies() {
        let signer = ManifestSigner::from_seed([7; 32]);
        let root = ManifestCatalog::sample().root(&signer);
        let envelope = signer.sign(&root).expect("sign root");
        let verified = signer.verify(&envelope).expect("verify root");
        assert_eq!(verified.version, 1);
    }

    #[test]
    fn shards_only_show_approved_records() {
        let catalog = ManifestCatalog::sample();
        let shard_name = catalog
            .shard_names(Ecosystem::Npm)
            .into_iter()
            .next()
            .expect("npm shard");
        let shard = catalog.shard(Ecosystem::Npm, &shard_name);
        assert!(
            shard
                .records
                .iter()
                .all(|record| record.status == crate::types::ApprovalStatus::Approved)
        );
    }

    #[test]
    fn digest_is_stable() {
        assert_eq!(digest_for("abc"), digest_for("abc"));
    }

    #[test]
    fn approved_visible_records_hide_pending_and_blocked() {
        let catalog = ManifestCatalog::sample();
        let visible = catalog.approved_visible_records();
        assert!(
            visible
                .iter()
                .all(|record| record.status == crate::types::ApprovalStatus::Approved)
        );
        assert!(
            visible
                .iter()
                .all(|record| record.requested_selector != "4.17.22")
        );
    }

    #[test]
    fn root_and_shards_are_signed_over_approved_records_only() {
        let signer = ManifestSigner::from_seed([7; 32]);
        let catalog = ManifestCatalog::sample();
        let root = catalog.root(&signer);
        assert!(root.shards.iter().all(|shard| shard.record_count > 0));
        assert!(
            root.shards
                .iter()
                .any(|shard| shard.ecosystem == Ecosystem::Git)
        );

        let npm_shard_name = catalog
            .shard_names(Ecosystem::Npm)
            .into_iter()
            .next()
            .expect("npm shard");
        let shard = catalog.shard(Ecosystem::Npm, &npm_shard_name);
        assert!(
            shard
                .records
                .iter()
                .all(|record| record.status == crate::types::ApprovalStatus::Approved)
        );
        assert!(
            shard
                .records
                .iter()
                .all(|record| record.requested_selector != "4.17.22")
        );

        let envelope = signer.sign(&root).expect("sign root");
        let verified = signer.verify(&envelope).expect("verify root");
        assert_eq!(verified.version, root.version);
    }

    #[test]
    fn exact_lookup_prefers_latest_record_for_same_selector() {
        let now = Utc::now();
        let coordinate = ArtifactCoordinate {
            ecosystem: Ecosystem::Git,
            source: "https://github.com/acme/retry-demo.git".to_string(),
            requested_selector: "git-smart-http".to_string(),
            selector_kind: SelectorKind::Floating,
        };
        let catalog = ManifestCatalog::new(vec![
            ManifestRecord {
                ecosystem: Ecosystem::Git,
                source: coordinate.source.clone(),
                requested_selector: coordinate.requested_selector.clone(),
                selector_kind: coordinate.selector_kind,
                resolved_target: "old-pending".to_string(),
                raw_digest_sha256: digest_for("old-pending"),
                normalized_digest_sha256: digest_for("tree:old-pending"),
                status: ApprovalStatus::Pending,
                first_seen_at: now - TimeDelta::minutes(10),
                hold_until: Some(now + TimeDelta::hours(1)),
                approved_at: None,
                fallback: None,
                detector_refs: vec![],
                metadata: Default::default(),
            },
            ManifestRecord {
                ecosystem: Ecosystem::Git,
                source: coordinate.source.clone(),
                requested_selector: coordinate.requested_selector.clone(),
                selector_kind: coordinate.selector_kind,
                resolved_target: "new-approved".to_string(),
                raw_digest_sha256: digest_for("new-approved"),
                normalized_digest_sha256: digest_for("tree:new-approved"),
                status: ApprovalStatus::Approved,
                first_seen_at: now,
                hold_until: None,
                approved_at: Some(now),
                fallback: None,
                detector_refs: vec![],
                metadata: Default::default(),
            },
        ]);

        let record = catalog.find_exact(&coordinate).expect("record");
        assert_eq!(record.status, ApprovalStatus::Approved);
        assert_eq!(record.resolved_target, "new-approved");
    }
}
