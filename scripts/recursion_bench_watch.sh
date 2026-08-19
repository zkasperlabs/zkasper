#!/bin/bash
# Poll the rented box's bench log and emit new milestone lines.
HOST=${HOST:-root@ssh3.vast.ai}
PORT=${PORT:-26792}
PREV=$(mktemp)
CUR=$(mktemp)
for i in $(seq 1 200); do
  timeout 60 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -p "$PORT" "$HOST" 'grep -E "^=== |^--- |Proof generated|WRONG ZISK|^STEPS|^TOTAL|WALL |No such file|rror|panicked" /root/bench.log' > "$CUR" 2>/dev/null
  comm -13 "$PREV" "$CUR" 2>/dev/null
  cp "$CUR" "$PREV"
  grep -q "=== 6. Done" "$CUR" && break
  sleep 45
done
