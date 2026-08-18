#!/usr/bin/env bash
# Put the agent on this box. Idempotent — run it again after editing any config.
#
#   sudo ./monitoring/install.sh
#
# It does not touch Grafana Cloud. That needs an account, and grafana_cloud.sh
# is what arms it once there is one.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
textfile=/var/lib/prometheus/node-exporter

command -v prometheus >/dev/null || {
  echo "prometheus is not installed: apt-get install prometheus prometheus-node-exporter" >&2
  exit 1
}

# node_exporter has to read the textfile collector directory, or the GPU cost
# metrics are written and never scraped. Debian ships the directory and not the
# flag that reads it.
mkdir -p "$textfile"
if ! grep -q collector.textfile /etc/default/prometheus-node-exporter; then
  sed -i "s|^ARGS=.*|ARGS=\"--collector.textfile.directory=$textfile\"|" \
    /etc/default/prometheus-node-exporter
fi

install -m 0644 "$here/alerts.yml" /etc/prometheus/zkasper-alerts.yml
# Keep whatever remote_write grafana_cloud.sh appended: this file is the base,
# and that block is the only thing allowed to outlive it.
if grep -q '^remote_write:' /etc/prometheus/prometheus.yml 2>/dev/null; then
  sed -n '/^remote_write:/,$p' /etc/prometheus/prometheus.yml > /tmp/zkasper-remote-write.yml
  cat "$here/prometheus.yml" /tmp/zkasper-remote-write.yml > /etc/prometheus/prometheus.yml
  rm -f /tmp/zkasper-remote-write.yml
else
  install -m 0644 "$here/prometheus.yml" /etc/prometheus/prometheus.yml
fi
promtool check config /etc/prometheus/prometheus.yml

# Poll the GPU provider often enough that a card left running is caught in
# minutes, and rarely enough that the account's rate limit never notices.
#
# The exporter is copied out of the repository rather than run from it. A cron
# entry pointing into a checkout breaks the moment that checkout is a worktree
# that gets cleaned up, a branch that gets switched, or a directory that gets
# moved — and it breaks silently, which is the one failure mode a cost alert
# must not have. Re-run this script after editing the exporter.
exporter=/usr/local/bin/zkasper-vast-exporter
install -m 0755 "$here/vast_exporter.py" "$exporter"

cron=/etc/cron.d/zkasper-vast-exporter
cat > "$cron" <<EOF
# What the GPU account is renting, into node_exporter's textfile collector.
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin
*/2 * * * * root $exporter >> /var/log/zkasper-vast-exporter.log 2>&1
EOF
chmod 0644 "$cron"
"$exporter"

systemctl restart prometheus-node-exporter
systemctl reload prometheus || systemctl restart prometheus

echo "installed. targets:"
sleep 3
curl -s 'http://localhost:9090/api/v1/targets?state=active' \
  | python3 -c 'import json,sys; [print(" ", t["labels"]["job"], t["health"]) for t in json.load(sys.stdin)["data"]["activeTargets"]]'
