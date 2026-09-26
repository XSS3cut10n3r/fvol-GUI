#!/bin/bash
# Pass-2 driver on the VM (run from ~/rsvol-bench with nohup/setsid): Windows round, Linux round,
# startup table, with /proc/loadavg sampled every 10 s. Results in ~/rsvol-bench/p2/.
set -u
cd ~/rsvol-bench
P=p2
mkdir -p $P out cache2
( while :; do echo "$(date +%T) $(cat /proc/loadavg)" >> $P/load.log; sleep 10; done ) &
SAMPLER=$!
trap 'kill $SAMPLER' EXIT
echo "start $(date -Is)" >> $P/timeline.txt
cat img/memory-dirty.raw img/rsvol-noble-6.8.0-139.elf > /dev/null

echo "windows $(date -Is)" >> $P/timeline.txt
python3 $P/bench2_vm.py $P/plugins_win.txt $P/win.tsv $P/win.jsonl --runs 5 --py-runs 2 \
  --py-ref raw_win.jsonl \
  --py-fresh isfinfo.IsfInfo,frameworkinfo.FrameworkInfo,windows.windows.Windows \
  --py-nowarm windows.statistics.Statistics,timeliner.Timeliner \
  --keep isfinfo.IsfInfo,frameworkinfo.FrameworkInfo,windows.windows.Windows,timeliner.Timeliner \
  --keep-dir $P/keep_win > $P/win.log 2>&1

echo "linux $(date -Is)" >> $P/timeline.txt
IMG=$HOME/rsvol-bench/img/rsvol-noble-6.8.0-139.elf EXTRA="-s $HOME/rsvol-bench/isf" \
python3 $P/bench2_vm.py $P/plugins_linux.txt $P/linux.tsv $P/linux.jsonl --runs 5 --py-runs 1 \
  --py-ref raw_linux.jsonl \
  --py-nowarm linux.pscallstack.PsCallStack,timeliner.Timeliner,linux.pagecache.RecoverFs \
  --keep timeliner.Timeliner --keep-dir $P/keep_linux > $P/linux.log 2>&1

echo "startup $(date -Is)" >> $P/timeline.txt
python3 $P/startup2_vm.py $P/startup.tsv > $P/startup.log 2>&1
echo "end $(date -Is)" >> $P/timeline.txt
