#!/bin/bash
# ALWAYS build/test through this wrapper when several agents are active:
#   /home/user/rs-vol/bench/scripts/cargo.sh build --profile fast
#   /home/user/rs-vol/bench/scripts/cargo.sh test --profile fast some_filter
# At most CARGO_SLOTS (default 5) cargo invocations run machine-wide; each is memory-capped
# (CARGO_MEM, default 6G) in its own systemd scope, so a runaway build/test can't take the session down.
exec /home/user/rs-vol/bench/scripts/limit.sh -p cargo -s ${CARGO_SLOTS:-5} -m ${CARGO_MEM:-6G} cargo "$@"
