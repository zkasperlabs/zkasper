#!/usr/bin/env bash
# Point this box's Prometheus at Grafana Cloud, and put the alert rules there.
#
# Run this once, after the account exists:
#
#   sudo ./monitoring/grafana_cloud.sh
#
# It reads the credentials from /root/.openclaw/workspace/.grafana-cloud, which
# has to hold three lines and nothing else:
#
#   url=https://prometheus-prod-NN-prod-REGION.grafana.net/api/prom/push
#   username=1234567
#   token=glc_...
#
# Take them from Grafana Cloud -> Connections -> Add new connection ->
# Hosted Prometheus metrics -> "Send metrics from a single Prometheus instance".
# The token is an access policy token with the metrics:write scope.
#
# The token never lands in the repository. It is copied to a mode-600 file that
# the prometheus user can read, and the config refers to it by path.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
creds=/root/.openclaw/workspace/.grafana-cloud
secret=/etc/prometheus/grafana-cloud.token

[ -r "$creds" ] || { echo "no credentials at $creds — see the header of this script" >&2; exit 1; }
url=$(grep -oP '(?<=^url=).*' "$creds")
username=$(grep -oP '(?<=^username=).*' "$creds")
token=$(grep -oP '(?<=^token=).*' "$creds")
[ -n "$url" ] && [ -n "$username" ] && [ -n "$token" ] || {
  echo "$creds needs url=, username= and token=" >&2; exit 1; }

install -m 0600 -o prometheus -g prometheus /dev/null "$secret"
printf '%s' "$token" > "$secret"

# The base config, plus the block that ships everything out. Rewritten whole
# rather than patched, so running this twice cannot leave two of them.
{
  cat "$here/prometheus.yml"
  cat <<EOF

# Push, not pull: this box has no inbound access, so it reaches out. Every
# series carries the external_labels above, which is what tells one daemon's
# metrics from another's.
remote_write:
  - url: $url
    basic_auth:
      username: $username
      password_file: $secret
EOF
} > /etc/prometheus/prometheus.yml
promtool check config /etc/prometheus/prometheus.yml
systemctl reload prometheus || systemctl restart prometheus

echo "remote_write armed. Now put the same rules in the cloud, so an alert about"
echo "this box is not evaluated only on this box:"
echo
echo "  mimirtool rules load monitoring/alerts.yml \\"
echo "    --address=https://prometheus-prod-NN-prod-REGION.grafana.net \\"
echo "    --id=$username --key=\$(cat $secret)"
echo
echo "Then Grafana Cloud -> Alerts & IRM -> Alert rules -> Notification policies,"
echo "and route severity=page somewhere that makes a noise."
