#!/bin/bash
# Temporary image builder only. It holds no protocol identity or FHE share.
set -euo pipefail
exec > >(tee -a /var/log/vcfhe-image-builder.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=5 update
apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=5 install -y ca-certificates curl gnupg python3
install -m 0755 -d /etc/apt/keyrings
curl --retry 5 --retry-all-errors -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable\n' "$(dpkg --print-architecture)" > /etc/apt/sources.list.d/docker.list
apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=5 update
apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=5 install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
systemctl enable --now docker
install -d -m 0700 /srv/vcfhe-build
printf 'Builder dependencies ready. No evaluation started.\n'
