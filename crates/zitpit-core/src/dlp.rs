use std::{
    io::{Cursor, Read},
    sync::LazyLock,
};

use flate2::read::GzDecoder;
use regex::Regex;
use sha2::{Digest, Sha256};
use tar::Archive;
use zip::read::ZipArchive;

use crate::egress::{ContentEncoding, DlpMatch, DlpVerdict, PayloadClass};

const MAX_SCAN_BYTES: usize = 256 * 1024;
const MAX_ARCHIVE_DEPTH: usize = 2;
const MAX_ARCHIVE_ENTRIES: usize = 16;
const MAX_ARCHIVE_ENTRY_BYTES: usize = 128 * 1024;

static PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP|[A-Z ]+)? ?PRIVATE KEY-----").unwrap()
});
static AWS_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").unwrap());
static AWS_SECRET_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{32,}['"]?"#).unwrap()
});
static GITHUB_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b").unwrap());
static ANTHROPIC_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b").unwrap());
static OPENAI_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-[A-Za-z0-9]{20,}\b").unwrap());
static ENV_CREDENTIAL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?im)^(?:export\s+)?(?:password|passwd|api[_\-]?key|secret|token|auth[_\-]?token)\s*=\s*['"]?[^'"\n]{6,}['"]?$"#,
    )
    .unwrap()
});
static BROWSER_SESSION_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:__secure-next-auth\.session-token|sessionid|connect\.sid|auth_token|cf_clearance)\s*[=:]\s*['"]?[A-Za-z0-9._%-]{12,}"#,
    )
    .unwrap()
});
static KUBECONFIG_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)apiVersion:\s*v1.*clusters:.*users:.*current-context:").unwrap()
});
static TERRAFORM_STATE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)"terraform_version":.*"resources":.*"instances":"#).unwrap()
});
static PHI_MRN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bMRN[:# ]\s*\d{6,10}\b").unwrap());
static PHI_SSN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:SSN|Social Security Number)[:# ]\s*\d{3}-\d{2}-\d{4}\b").unwrap()
});
static DOB_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:dob|date of birth)[: ]+\d{4}-\d{2}-\d{2}\b").unwrap());
static PERSON_NAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^name:\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+$").unwrap());
static DIAGNOSIS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:diagnosis|treatment|patient|medication|clinic|physician)\b").unwrap()
});
static PII_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
static INTERNAL_HOST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9-]+\.)+(?:internal|corp|cluster\.local)\b").unwrap()
});
static RFC1918_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b").unwrap()
});
static GIT_CONFIG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?is)\[remote ".+?"\].*url\s*="#).unwrap());
static SOURCE_LINE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:fn\s+\w+|class\s+\w+|import\s+\w+|from\s+\w+\s+import|package\s+\w+|use\s+\w+::)").unwrap()
});
static MODEL_INTERNAL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:system prompt|assistant instructions|mcp server|claude\.md|tool call)\b")
        .unwrap()
});

pub fn scan_payload(chunk: &[u8]) -> DlpVerdict {
    scan_payload_with_depth(chunk, 0)
}

fn scan_payload_with_depth(chunk: &[u8], depth: usize) -> DlpVerdict {
    let clipped = if chunk.len() > MAX_SCAN_BYTES {
        &chunk[..MAX_SCAN_BYTES]
    } else {
        chunk
    };

    let mut verdict = DlpVerdict {
        is_clean: true,
        matches: vec![],
        analyzed_bytes: clipped.len(),
        archive_unpacked: false,
        encoding: detect_encoding(clipped),
        payload_sha256: hex::encode(Sha256::digest(clipped)),
        inspection_error: None,
    };

    scan_textual_detectors(clipped, &mut verdict);

    if depth < MAX_ARCHIVE_DEPTH {
        match verdict.encoding {
            ContentEncoding::Gzip => scan_gzip_archive(clipped, depth + 1, &mut verdict),
            ContentEncoding::Zip => scan_zip_archive(clipped, depth + 1, &mut verdict),
            ContentEncoding::Tar => scan_tar_archive(clipped, depth + 1, &mut verdict),
            _ => {}
        }
    }

    verdict
        .matches
        .sort_by_key(|m| (m.index_start, m.index_end));
    verdict.matches.dedup_by(|a, b| {
        a.detector_id == b.detector_id && a.class == b.class && a.index_start == b.index_start
    });
    verdict.is_clean = verdict.matches.is_empty();
    verdict
}

fn scan_textual_detectors(chunk: &[u8], verdict: &mut DlpVerdict) {
    let payload = String::from_utf8_lossy(chunk);
    find_first(
        &payload,
        &PRIVATE_KEY_REGEX,
        "private_key_header",
        PayloadClass::PrivateKeyMaterial,
        verdict,
    );
    find_first(
        &payload,
        &AWS_KEY_REGEX,
        "aws_access_key",
        PayloadClass::ApiToken,
        verdict,
    );
    find_first(
        &payload,
        &AWS_SECRET_REGEX,
        "aws_secret_access_key",
        PayloadClass::Credentials,
        verdict,
    );
    find_first(
        &payload,
        &GITHUB_TOKEN_REGEX,
        "github_token",
        PayloadClass::ApiToken,
        verdict,
    );
    find_first(
        &payload,
        &ANTHROPIC_KEY_REGEX,
        "anthropic_api_key",
        PayloadClass::ApiToken,
        verdict,
    );
    find_first(
        &payload,
        &OPENAI_KEY_REGEX,
        "openai_api_key",
        PayloadClass::ApiToken,
        verdict,
    );
    find_first(
        &payload,
        &ENV_CREDENTIAL_REGEX,
        "env_style_credential",
        PayloadClass::Credentials,
        verdict,
    );
    find_first(
        &payload,
        &BROWSER_SESSION_REGEX,
        "browser_session_token",
        PayloadClass::BrowserSession,
        verdict,
    );
    find_first(
        &payload,
        &KUBECONFIG_REGEX,
        "kubeconfig_bundle",
        PayloadClass::InfrastructureState,
        verdict,
    );
    find_first(
        &payload,
        &TERRAFORM_STATE_REGEX,
        "terraform_state",
        PayloadClass::InfrastructureState,
        verdict,
    );
    find_first(
        &payload,
        &PHI_MRN_REGEX,
        "phi_mrn",
        PayloadClass::RegulatedPhi,
        verdict,
    );
    find_first(
        &payload,
        &PHI_SSN_REGEX,
        "phi_ssn",
        PayloadClass::RegulatedPhi,
        verdict,
    );
    find_first(
        &payload,
        &PII_REGEX,
        "pii_ssn_like",
        PayloadClass::RegulatedPii,
        verdict,
    );
    find_first(
        &payload,
        &INTERNAL_HOST_REGEX,
        "internal_hostname",
        PayloadClass::InternalTopology,
        verdict,
    );
    find_first(
        &payload,
        &RFC1918_REGEX,
        "rfc1918_topology",
        PayloadClass::InternalTopology,
        verdict,
    );
    find_first(
        &payload,
        &GIT_CONFIG_REGEX,
        "git_remote_config",
        PayloadClass::SourceCode,
        verdict,
    );
    find_first(
        &payload,
        &MODEL_INTERNAL_REGEX,
        "model_agent_internal",
        PayloadClass::ModelAgentInternal,
        verdict,
    );

    if looks_like_phi_record(&payload) {
        verdict.matches.push(DlpMatch {
            detector_id: "phi_record_heuristic".to_string(),
            class: PayloadClass::RegulatedPhi,
            index_start: 0,
            index_end: payload.len().min(64),
            snippet: None,
        });
    }

    if looks_like_source_code(&payload) {
        verdict.matches.push(DlpMatch {
            detector_id: "source_density".to_string(),
            class: PayloadClass::SourceCode,
            index_start: 0,
            index_end: payload.len().min(64),
            snippet: None,
        });
    }
}

fn find_first(
    payload: &str,
    regex: &Regex,
    detector_id: &str,
    class: PayloadClass,
    verdict: &mut DlpVerdict,
) {
    if let Some(m) = regex.find(payload) {
        verdict.matches.push(DlpMatch {
            detector_id: detector_id.to_string(),
            class,
            index_start: m.start(),
            index_end: m.end(),
            snippet: None,
        });
    }
}

fn looks_like_phi_record(payload: &str) -> bool {
    let has_name = PERSON_NAME_REGEX.is_match(payload);
    let has_dob = DOB_REGEX.is_match(payload);
    let has_medical_context = DIAGNOSIS_REGEX.is_match(payload);
    (has_name && has_dob && has_medical_context)
        || (PHI_MRN_REGEX.is_match(payload) && has_medical_context)
}

fn looks_like_source_code(payload: &str) -> bool {
    let source_lines = SOURCE_LINE_REGEX.find_iter(payload).count();
    let newline_count = payload.lines().take(80).count();
    source_lines >= 3 || (newline_count >= 6 && source_lines >= 2)
}

fn detect_encoding(chunk: &[u8]) -> ContentEncoding {
    if chunk.starts_with(&[0x1f, 0x8b]) {
        ContentEncoding::Gzip
    } else if chunk.starts_with(b"PK\x03\x04") || chunk.starts_with(b"PK\x05\x06") {
        ContentEncoding::Zip
    } else if chunk.len() > 262 && &chunk[257..262] == b"ustar" {
        ContentEncoding::Tar
    } else {
        ContentEncoding::Plaintext
    }
}

fn scan_gzip_archive(chunk: &[u8], depth: usize, verdict: &mut DlpVerdict) {
    let mut decoder = GzDecoder::new(Cursor::new(chunk));
    let mut unpacked = Vec::with_capacity(MAX_ARCHIVE_ENTRY_BYTES.min(chunk.len() * 4));
    let limited = (&mut decoder).take(MAX_ARCHIVE_ENTRY_BYTES as u64);
    let mut limited = limited;
    if let Err(error) = limited.read_to_end(&mut unpacked) {
        verdict.inspection_error = Some(format!("gzip unpack failed: {error}"));
        verdict.encoding = ContentEncoding::Unknown;
        return;
    }
    verdict.archive_unpacked = true;
    merge_nested_verdict(verdict, scan_payload_with_depth(&unpacked, depth));
}

fn scan_tar_archive(chunk: &[u8], depth: usize, verdict: &mut DlpVerdict) {
    let mut archive = Archive::new(Cursor::new(chunk));
    let Ok(entries) = archive.entries() else {
        verdict.inspection_error = Some("tar archive could not be enumerated".to_string());
        verdict.encoding = ContentEncoding::Unknown;
        return;
    };

    for (index, entry) in entries.take(MAX_ARCHIVE_ENTRIES).enumerate() {
        let Ok(mut entry) = entry else {
            verdict.inspection_error = Some("tar entry could not be read".to_string());
            verdict.encoding = ContentEncoding::Unknown;
            return;
        };
        let mut buf = Vec::new();
        let mut limited = (&mut entry).take(MAX_ARCHIVE_ENTRY_BYTES as u64);
        if let Err(error) = limited.read_to_end(&mut buf) {
            verdict.inspection_error = Some(format!("tar entry {index} read failed: {error}"));
            verdict.encoding = ContentEncoding::Unknown;
            return;
        }
        verdict.archive_unpacked = true;
        merge_nested_verdict(verdict, scan_payload_with_depth(&buf, depth));
        if verdict.inspection_error.is_some() {
            return;
        }
    }
}

fn scan_zip_archive(chunk: &[u8], depth: usize, verdict: &mut DlpVerdict) {
    let cursor = Cursor::new(chunk);
    let Ok(mut archive) = ZipArchive::new(cursor) else {
        verdict.inspection_error = Some("zip archive could not be opened".to_string());
        verdict.encoding = ContentEncoding::Unknown;
        return;
    };

    for index in 0..archive.len().min(MAX_ARCHIVE_ENTRIES) {
        let Ok(mut file) = archive.by_index(index) else {
            verdict.inspection_error = Some("zip entry could not be opened".to_string());
            verdict.encoding = ContentEncoding::Unknown;
            return;
        };
        if file.encrypted() {
            verdict.inspection_error = Some("encrypted zip entry".to_string());
            verdict.encoding = ContentEncoding::Encrypted;
            return;
        }
        let mut buf = Vec::new();
        let mut limited = (&mut file).take(MAX_ARCHIVE_ENTRY_BYTES as u64);
        if let Err(error) = limited.read_to_end(&mut buf) {
            verdict.inspection_error = Some(format!("zip entry {index} read failed: {error}"));
            verdict.encoding = ContentEncoding::Unknown;
            return;
        }
        verdict.archive_unpacked = true;
        merge_nested_verdict(verdict, scan_payload_with_depth(&buf, depth));
        if verdict.inspection_error.is_some() {
            return;
        }
    }
}

fn merge_nested_verdict(into: &mut DlpVerdict, nested: DlpVerdict) {
    into.matches.extend(nested.matches);
    into.archive_unpacked |= nested.archive_unpacked;
    into.analyzed_bytes = into.analyzed_bytes.saturating_add(nested.analyzed_bytes);
    if into.inspection_error.is_none() {
        into.inspection_error = nested.inspection_error;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};
    use zip::write::SimpleFileOptions;

    use super::*;

    #[test]
    fn detects_private_key_material() {
        let payload = b"-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n";
        let verdict = scan_payload(payload);
        assert!(!verdict.is_clean);
        assert_eq!(verdict.matches[0].class, PayloadClass::PrivateKeyMaterial);
    }

    #[test]
    fn detects_env_style_credentials() {
        let payload = b"API_KEY=supersecretvalue";
        let verdict = scan_payload(payload);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::Credentials)
        );
    }

    #[test]
    fn detects_browser_session_tokens() {
        let payload = b"connect.sid=s%3Along-session-token-value";
        let verdict = scan_payload(payload);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::BrowserSession)
        );
    }

    #[test]
    fn detects_kubeconfig_and_terraform_state() {
        let payload = b"apiVersion: v1\nclusters:\n- cluster:\nusers:\ncurrent-context: prod\n";
        let verdict = scan_payload(payload);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::InfrastructureState)
        );
    }

    #[test]
    fn detects_phi_heuristics() {
        let payload = b"Name: Jane Smith\nDOB: 1988-01-31\nDiagnosis: hypertension\n";
        let verdict = scan_payload(payload);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::RegulatedPhi)
        );
    }

    #[test]
    fn detects_source_code_density() {
        let payload = b"use std::fs;\nfn main() {}\nimport os\nclass Demo:\n    pass\n";
        let verdict = scan_payload(payload);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::SourceCode)
        );
    }

    #[test]
    fn detects_internal_topology() {
        let payload = b"db.internal\n10.42.0.15\n";
        let verdict = scan_payload(payload);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::InternalTopology)
        );
    }

    #[test]
    fn scans_gzip_archives() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(b"-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n")
            .unwrap();
        let payload = encoder.finish().unwrap();
        let verdict = scan_payload(&payload);
        assert!(verdict.archive_unpacked);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::PrivateKeyMaterial)
        );
    }

    #[test]
    fn scans_tar_archives() {
        let mut archive = Builder::new(Vec::new());
        let body = b"API_KEY=secretbundle";
        let mut header = Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "creds.env", Cursor::new(body))
            .unwrap();
        let payload = archive.into_inner().unwrap();
        let verdict = scan_payload(&payload);
        assert!(verdict.archive_unpacked);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::Credentials)
        );
    }

    #[test]
    fn scans_zip_archives() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            writer
                .start_file("report.csv", SimpleFileOptions::default())
                .unwrap();
            writer
                .write_all(b"Name: Jane Smith\nDOB: 1988-01-31\nDiagnosis: asthma\n")
                .unwrap();
            writer.finish().unwrap();
        }
        let payload = cursor.into_inner();
        let verdict = scan_payload(&payload);
        assert!(verdict.archive_unpacked);
        assert!(
            verdict
                .matches
                .iter()
                .any(|m| m.class == PayloadClass::RegulatedPhi)
        );
    }

    #[test]
    fn benign_payload_stays_clean() {
        let verdict = scan_payload(b"{\"status\":\"ok\"}");
        assert!(verdict.is_clean);
        assert!(verdict.inspection_error.is_none());
    }
}
