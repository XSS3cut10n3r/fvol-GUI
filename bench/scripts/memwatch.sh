#!/bin/bash
# Memory watchdog (safety net against systemd-oomd killing the whole terminal scope).
# When MemAvailable drops below THRESH_MB, SIGKILL the largest-RSS heavy worker process
# (python/rustc/test binaries/vol/cargo), never claude itself. Logs to bench/memwatch.log.
THRESH_MB=${THRESH_MB:-7000}
LOG=/home/user/fvol/bench/memwatch.log
while true; do
  avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
  if [ "$avail" -lt "$THRESH_MB" ]; then
    victim=$(ps -u "$(id -un)" -o pid=,rss=,comm= --sort=-rss | awk '$3 ~ /^(python|python3|rustc|cargo|vol|fvol|fastvol|rsvol|ld|cc1|cc1plus|gcc|g\+\+|capstone|yara)/ || $3 ~ /-[0-9a-f]{16}$/ {print $1, $2, $3; exit}')
    if [ -n "$victim" ]; then
      set -- $victim
      kill -9 $1 && echo "$(date '+%F %T') avail=${avail}MB killed pid=$1 rss=$(($2/1024))MB comm=$3" >> $LOG
    fi
    sleep 1
  else
    sleep 2
  fi
done
