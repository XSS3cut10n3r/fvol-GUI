#!/bin/bash
# Pass-3 driver on the VM (run from ~/rsvol-bench with nohup/setsid): the optimized build's three
# cache-state columns only; python reused from pass 1, vol-rs from pass 2 (same VM, same builds).
# Usage: RS_BIN=~/rsvol-bench/<checkout>/target/release/fvol run3.sh   Results in ~/rsvol-bench/p3/.
set -u
cd ~/rsvol-bench
: "${RS_BIN:?set RS_BIN to the binary under test}"
export RS_BIN
P=p3
mkdir -p $P out cache2
cp p2/plugins_win.txt p2/plugins_linux.txt $P/ 2>/dev/null
( while :; do echo "$(date +%T) $(cat /proc/loadavg)" >> $P/load.log; sleep 10; done ) &
SAMPLER=$!
trap 'kill $SAMPLER' EXIT
echo "start $(date -Is) $RS_BIN $(sha256sum "$RS_BIN" | cut -c1-16)" >> $P/timeline.txt
cat img/memory-dirty.raw img/rsvol-noble-6.8.0-139.elf > /dev/null
rm -rf cache2/rs-cold cache2/rs-steady cache2/rs-warm

echo "windows $(date -Is)" >> $P/timeline.txt
python3 $P/bench2_vm.py $P/plugins_win.txt $P/win.tsv $P/win.jsonl --runs 5 \
  --py-ref raw_win.jsonl,p2/win.jsonl --vr-ref p2/win.jsonl \
  --keep isfinfo.IsfInfo,frameworkinfo.FrameworkInfo,windows.windows.Windows,timeliner.Timeliner \
  --keep-dir $P/keep_win > $P/win.log 2>&1

echo "linux $(date -Is)" >> $P/timeline.txt
IMG=$HOME/rsvol-bench/img/rsvol-noble-6.8.0-139.elf EXTRA="-s $HOME/rsvol-bench/isf" \
python3 $P/bench2_vm.py $P/plugins_linux.txt $P/linux.tsv $P/linux.jsonl --runs 5 \
  --py-ref raw_linux.jsonl,p2/linux.jsonl --vr-ref p2/linux.jsonl \
  --keep timeliner.Timeliner --keep-dir $P/keep_linux > $P/linux.log 2>&1

echo "startup $(date -Is)" >> $P/timeline.txt
python3 $P/startup2_vm.py $P/startup.tsv > $P/startup.log 2>&1
echo "end $(date -Is)" >> $P/timeline.txt
