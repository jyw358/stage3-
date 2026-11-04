#!/bin/bash
export XDG_RUNTIME_DIR=/run/user/1000
SOCK=unix:///data/cybergym-rootless/docker.sock
OUT=/data/cybergym/stage3/replay_results.txt
: > $OUT
while IFS= read -r cmd; do
  [ -z "$cmd" ] && continue
  case "$cmd" in docker*) fixed="${cmd/#docker /docker -H $SOCK }";; *) fixed="docker -H $SOCK $cmd";; esac
  timeout 9 bash -c "$fixed" >/dev/null 2>/tmp/replay_err.txt
  rc=$?
  err=$(head -c 150 /tmp/replay_err.txt | tr '\n' ' ')
  echo "RC=$rc ERR=$err CMD=${cmd:0:110}" >> $OUT
done < /data/cybergym/stage3/replay_sample.txt
echo REPLAY-DONE >> $OUT
