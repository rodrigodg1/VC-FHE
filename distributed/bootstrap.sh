#!/bin/bash
# GCE startup: install Docker and mount only this experiment's retained disk.
# Does not start validators, KMS, application roles, a pilot or measurements.
set -euo pipefail
exec > >(tee -a /var/log/vcfhe-bootstrap.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
retry() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if "$@"; then return 0; fi
    sleep "$((attempt * 3))"
  done
  return 1
}
# Bootstrap downloads may retry. Protocol operations are never retried here.
retry apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 update
retry apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 install -y ca-certificates curl gnupg python3 chrony
metadata() { curl --fail --silent --show-error --retry 4 -H 'Metadata-Flavor: Google' "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
campaign="$(metadata vcfhe-campaign)"
host_id="$(metadata vcfhe-host)"
[[ "$campaign" =~ ^[a-z][a-z0-9-]{2,20}$ ]]
[[ "$host_id" =~ ^[a-z]+-[0-9]+$ ]]
install -m 0755 -d /etc/apt/keyrings
curl --retry 4 --retry-all-errors -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable\n' "$(dpkg --print-architecture)" > /etc/apt/sources.list.d/docker.list
retry apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 update
retry apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker chrony
device=/dev/disk/by-id/google-vcfhe-state
test -b "$device"
fs_type="$(blkid -s TYPE -o value "$device" || true)"
if [ -z "$fs_type" ]; then
  # Refuse an unknown signature. Only a new empty state disk may be formatted.
  test -z "$(wipefs --no-act --noheadings --output TYPE "$device")"
  mkfs.ext4 "$device"
elif [ "$fs_type" != ext4 ]; then
  echo 'Unexpected existing state filesystem. Refusing to modify it.' >&2
  exit 1
fi
install -d -m 0700 /srv/vcfhe
uuid="$(blkid -s UUID -o value "$device")"
entry="UUID=$uuid /srv/vcfhe ext4 defaults 0 2"
if ! grep -Fxq "$entry" /etc/fstab; then
  if grep -Eq '[[:space:]]/srv/vcfhe[[:space:]]' /etc/fstab; then
    echo 'A different state volume is already configured.' >&2
    exit 1
  fi
  printf '%s\n' "$entry" >> /etc/fstab
fi
mountpoint -q /srv/vcfhe || mount /srv/vcfhe
marker=/srv/vcfhe/scope.txt
scope="$campaign/$host_id"
if [ -e "$marker" ]; then
  test "$(cat "$marker")" = "$scope"
else
  printf '%s\n' "$scope" > "$marker"
fi
install -d -m 0700 /srv/vcfhe/bootstrap-evidence
docker version > /srv/vcfhe/bootstrap-evidence/docker.txt
docker compose version > /srv/vcfhe/bootstrap-evidence/compose.txt
lscpu --json > /srv/vcfhe/bootstrap-evidence/cpu.json
dpkg-query -W > /srv/vcfhe/bootstrap-evidence/packages.txt
chronyc tracking > /srv/vcfhe/bootstrap-evidence/clock.txt
printf '%s\n' 'Infrastructure initialized. Protocol services have NOT started.'
