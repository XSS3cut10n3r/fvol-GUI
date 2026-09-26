#!/bin/bash
# Start / stop a `vol serve` instance for UI tests (memory-capped via limit.sh).
#   bench/web/serve.sh start NAME PORT IMAGE [extra vol serve args...]
#   bench/web/serve.sh stop NAME
# Logs and output dirs live under testdata/scratch/webui/NAME (disk, not tmpfs).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${BIN:-$ROOT/target/fast/vol}
SCR=/home/user/rs-vol/testdata/scratch/webui
cmd=$1; name=$2
dir=$SCR/$name
mkdir -p "$dir"
# the vol process itself (not the limit.sh / systemd-run wrappers)
volpid() { pgrep -f -- "^[^ ]*/vol serve .*--token testtoken-$name-0123456789" | head -1; }
stop() {
  local p; p=$(volpid)
  [ -n "$p" ] && kill "$p" 2>/dev/null
  for _ in $(seq 1 50); do [ -z "$(volpid)" ] && break; sleep 0.1; done
}
case $cmd in
  start)
    port=$3; img=$4; shift 4
    stop
    nohup /home/user/rs-vol/bench/scripts/limit.sh -m 6G "$BIN" serve -f "$img" --port "$port" \
      --token "testtoken-$name-0123456789" -o "$dir/out" "$@" > "$dir/serve.log" 2>&1 &
    for _ in $(seq 1 100); do
      pid=$(volpid)
      if [ -n "$pid" ] && curl -s -o /dev/null "http://127.0.0.1:$port/favicon.svg"; then
        echo "started $name on $port (pid $pid)"; exit 0
      fi
      sleep 0.1
    done
    echo "failed to start"; cat "$dir/serve.log"; exit 1;;
  stop) stop; echo "stopped $name";;
esac
