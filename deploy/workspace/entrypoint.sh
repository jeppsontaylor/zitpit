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
  install -m 0644 /usr/local/share/zitpit-workspace/zitpit-protected-zshrc \
    /etc/zitpit/zshrc.protected

  if ! grep -Fq 'source /etc/profile.d/zitpit-protected.sh' /etc/bash.bashrc; then
    cat >> /etc/bash.bashrc <<'EOF'

if [ -f /etc/profile.d/zitpit-protected.sh ]; then
  . /etc/profile.d/zitpit-protected.sh
fi
EOF
fi
}

install_user_shell_config() {
  cat > /home/z/.zshrc <<'EOF'
source /etc/zitpit/zshrc.protected
EOF

  cat > /home/z/.zprofile <<'EOF'
if [ -f /etc/profile.d/zitpit-protected.sh ]; then
  . /etc/profile.d/zitpit-protected.sh
fi
EOF
}

restrict_egress() {
  :
}

install -d -m 0700 /home/z/.ssh
cp /run/zitpit/authorized_key /home/z/.ssh/authorized_keys
install_workspace_ui
install_user_shell_config
chown z:z /home/z
chown -R z:z /home/z/.ssh /home/z/workspace /home/z/.zshrc /home/z/.zprofile
chmod 0600 /home/z/.ssh/authorized_keys

cat > /home/z/.gitconfig <<EOF
[http]
    proxy = ${ZITPIT_PROXY_URL}

[color]
    ui = always

[core]
    pager = less -RF

[url "http://github.com/"]
    insteadOf = https://github.com/
    insteadOf = ssh://git@github.com/
    insteadOf = git@github.com:

[url "http://gitlab.com/"]
    insteadOf = https://gitlab.com/
    insteadOf = ssh://git@gitlab.com/
    insteadOf = git@gitlab.com:
EOF

cat > /home/z/README_ZITPIT_DEMO.txt <<EOF
Approved demo repo:
${ZITPIT_APPROVED_REPO_URL}

Unknown demo repo:
${ZITPIT_UNKNOWN_REPO_URL}
EOF

chown z:z /home/z/.gitconfig /home/z/README_ZITPIT_DEMO.txt
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config.zitpit
