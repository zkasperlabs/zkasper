#!/bin/bash
# Block until the rented box reaches a marker in the bench log.
MARKER=${1:-"=== 5. Prove"}
for i in $(seq 1 240); do
  if timeout 60 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      -p 26792 root@ssh3.vast.ai "grep -qF '$MARKER' /root/bench.log" 2>/dev/null; then
    echo "reached: $MARKER"
    exit 0
  fi
  sleep 30
done
echo "timed out waiting for: $MARKER"
