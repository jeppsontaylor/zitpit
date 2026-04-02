use chrono::Utc;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use tokio::fs;

use crate::types::{NodeBootstrapBundle, NodeSession, PolicySnapshot};

#[derive(Debug, Default)]
pub struct NodeBootstrapper;

impl NodeBootstrapper {
    pub fn bootstrap(
        node_id: &str,
        hostname: &str,
        policy: PolicySnapshot,
    ) -> Result<NodeBootstrapBundle, rcgen::Error> {
        let mut params = CertificateParams::new(vec![])?;
        params
            .distinguished_name
            .push(DnType::CommonName, format!("ZitPit Root CA for {node_id}"));
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key_pair = KeyPair::generate()?;
        let issuer = CertifiedIssuer::self_signed(params, key_pair)?;

        Ok(NodeBootstrapBundle {
            node_id: node_id.to_string(),
            policy: policy.clone(),
            ca_cert_pem: issuer.pem(),
            ca_key_pem: issuer.key().serialize_pem(),
            nftables_ruleset: render_nftables_rules(hostname, &policy),
            install_script: render_install_script(
                node_id,
                hostname,
                &policy,
                issuer.pem().as_str(),
            ),
        })
    }

    pub async fn apply_bundle(
        bundle: &NodeBootstrapBundle,
        root: &std::path::Path,
    ) -> Result<(), std::io::Error> {
        let ca_path = root.join("usr/local/share/ca-certificates/zitpit-ca.crt");
        let nft_path = root.join("etc/nftables.d/zitpit.nft");
        let script_path = root.join("usr/local/bin/zitpit-apply-bootstrap");

        if let Some(parent) = ca_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        if let Some(parent) = nft_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        if let Some(parent) = script_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::write(&ca_path, bundle.ca_cert_pem.as_bytes()).await?;
        fs::write(&nft_path, bundle.nftables_ruleset.as_bytes()).await?;
        fs::write(&script_path, bundle.install_script.as_bytes()).await?;
        Ok(())
    }

    pub fn session(
        node_id: &str,
        hostname: &str,
        user_label: &str,
        policy: &PolicySnapshot,
    ) -> NodeSession {
        NodeSession {
            node_id: node_id.to_string(),
            user_label: user_label.to_string(),
            hostname: hostname.to_string(),
            policy_version: policy.version.clone(),
            ca_version: format!("ca-{}", policy.version),
            transparent_capture: policy.config.transparent_capture,
            last_seen_at: Utc::now(),
        }
    }
}

pub fn render_nftables_rules(hostname: &str, policy: &PolicySnapshot) -> String {
    let bypass_set = policy
        .config
        .bypass_hosts
        .iter()
        .map(|host| format!("\"{host}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "table inet zitpit {{\n  set bypass_hosts {{ type string; elements = {{ {bypass_set} }} }}\n  chain output {{\n    type nat hook output priority dstnat;\n    meta skuid 0 return\n    tcp dport {{80, 443}} redirect to :{proxy_port}\n  }}\n}}\n# generated for {hostname}\n",
        proxy_port = policy.config.proxy_port,
    )
}

pub fn render_install_script(
    node_id: &str,
    hostname: &str,
    policy: &PolicySnapshot,
    ca_cert_pem: &str,
) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

NODE_ID="{node_id}"
HOSTNAME="{hostname}"
PROXY_PORT="{proxy_port}"

install -d /usr/local/share/ca-certificates
cat > /usr/local/share/ca-certificates/zitpit-ca.crt <<'EOF_CA'
{ca_cert_pem}
EOF_CA
update-ca-certificates

install -d /etc/nftables.d
cat > /etc/nftables.d/zitpit.nft <<'EOF_NFT'
{nftables_ruleset}
EOF_NFT
nft -f /etc/nftables.d/zitpit.nft

cat > /usr/local/bin/zitpit-node-meta <<'EOF_META'
node_id={node_id}
hostname={hostname}
proxy_port={proxy_port}
admin_port={admin_port}
transparent_capture={transparent_capture}
EOF_META
chmod 0755 /usr/local/bin/zitpit-node-meta

echo "installed ZitPit node bootstrap for $NODE_ID"
"#,
        node_id = node_id,
        hostname = hostname,
        proxy_port = policy.config.proxy_port,
        admin_port = policy.config.admin_port,
        transparent_capture = policy.config.transparent_capture,
        ca_cert_pem = ca_cert_pem.trim(),
        nftables_ruleset = render_nftables_rules(hostname, policy).trim(),
    )
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::NodeBootstrapper;
    use crate::{PolicySnapshot, sample_policy};

    #[test]
    fn bootstrap_generates_ca_and_ruleset() {
        let bundle = NodeBootstrapper::bootstrap(
            "node-1",
            "devbox-1",
            PolicySnapshot {
                version: "v1".to_string(),
                generated_at: Utc::now(),
                config: sample_policy(),
            },
        )
        .expect("bootstrap");
        assert!(bundle.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(bundle.nftables_ruleset.contains("redirect to"));
        assert!(bundle.install_script.contains("update-ca-certificates"));
        assert!(bundle.install_script.contains("nft -f"));
        assert!(
            bundle
                .install_script
                .contains("installed ZitPit node bootstrap")
        );
    }
}
