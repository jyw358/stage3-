#!/bin/bash
ST=/data/cybergym/stage3/iso_status.txt
: > $ST
while ! grep -q 'PRELOAD-DONE' /data/cybergym/stage3/isolation_backup/preload.log 2>/dev/null; do sleep 10; done
echo "PRELOAD-COMPLETE $(date -u +%T)" >> $ST
runuser -u naco -- env XDG_RUNTIME_DIR=/run/user/1000 DOCKER_HOST=unix:///data/cybergym-rootless/docker.sock docker images --format x | wc -l >> $ST
runuser -u naco -- bash /data/cybergym/stage3/replay_run.sh
echo "REPLAY-COMPLETE $(date -u +%T)" >> $ST
runuser -u naco -- bash /data/cybergym/stage3/smoke_isolation.sh >> $ST 2>&1
echo "SMOKE-RC=$?" >> $ST
echo ORCHESTRATE-DONE >> $ST
