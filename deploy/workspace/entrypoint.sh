#!/usr/bin/env bash
set -euo pipefail

install_workspace_ui() {
  install -d -m 0755 /etc/zitpit /etc/profile.d
  install -m 0755 /usr/local/share/zitpit-workspace/protected-session.sh \
    /usr/local/bin/zitpit-protected-session
  install -m 0644 /usr/local/share/zitpit-workspace/sshd_config.zitpit \
    /etc/ssh/sshd_config.zitpit
  install -m 0644 /usr/local/share/zitpit-workspace/tmux-protected.conf \
    /etc/zitpit/tmux-protected.conf
  install -m 0644 /usr/local/share/zitpit-workspace/zitpit-protected-profile.sh \
    /etc/profile.d/zitpit-protected.sh

  if ! grep -Fq 'source /etc/profile.d/zitpit-protected.sh' /etc/bash.bashrc; then
    cat >> /etc/bash.bashrc <<'EOF'

if [ -f /etc/profile.d/zitpit-protected.sh ]; then
  . /etc/profile.d/zitpit-protected.sh
fi
EOF
  fi
}

restrict_egress() {
  local resolver="${ZITPIT_PROXY_URL#http://}"
  resolver="${resolver%%/*}"
  local proxy_host="${resolver%%:*}"
  local allowed_hosts=(
    "${proxy_host}"
    "zitpit-manifest"
    "zitpit-lab"
    "zitpit-watch"
    "zitpit-node-agent"
  )

  iptables -F OUTPUT
  iptables -P OUTPUT DROP
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  local host
  local addr
  for host in "${allowed_hosts[@]}"; do
    while read -r addr; do
      if [[ -n "${addr}" ]]; then
        iptables -A OUTPUT -d "${addr}" -j ACCEPT
      fi
    done < <(getent ahostsv4 "${host}" | awk '{print $1}' | sort -u)
  done
}

install -d -m 0700 /home/zitpit/.ssh
cp /run/zitpit/authorized_key /home/zitpit/.ssh/authorized_keys
chown zitpit:zitpit /home/zitpit
chown -R zitpit:zitpit /home/zitpit/.ssh /home/zitpit/workspace
chmod 0600 /home/zitpit/.ssh/authorized_keys

cat > /home/zitpit/.gitconfig <<EOF
[http]
    proxy = ${ZITPIT_PROXY_URL}

[url "http://github.com/"]
    insteadOf = https://github.com/
    insteadOf = ssh://git@github.com/
    insteadOf = git@github.com:

[url "http://gitlab.com/"]
    insteadOf = https://gitlab.com/
    insteadOf = ssh://git@gitlab.com/
    insteadOf = git@gitlab.com:
EOF

cat > /home/zitpit/README_ZITPIT_DEMO.txt <<EOF
Approved demo repo:
${ZITPIT_APPROVED_REPO_URL}

Unknown demo repo:
${ZITPIT_UNKNOWN_REPO_URL}
EOF

chown zitpit:zitpit /home/zitpit/.gitconfig /home/zitpit/README_ZITPIT_DEMO.txt
install_workspace_ui
restrict_egress
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config.zitpit
