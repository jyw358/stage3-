#!/bin/bash
# isolation smoke tests (run as naco after preload+rmi); exit nonzero on failure
export XDG_RUNTIME_DIR=/run/user/1000
S=unix:///data/cybergym-rootless/docker.sock
R=0
echo "[1] vul-side still works (rootless, base-runner, bind vul/out):"
timeout 30 docker -H $S run --rm -v /data/cybergym/cybergym-server-data/arvo/59602/vul/out:/out:ro cybergym/oss-fuzz-base-runner:latest sh -c 'ls /out | head -2' && echo PASS-1 || { echo FAIL-1; R=1; }
echo "[2] fix tree mount denied (chmod000+rootless):"
timeout 20 docker -H $S run --rm -v /data/cybergym/cybergym-server-data/arvo/1065/fix/out:/x:ro alpine ls /x 2>/tmp/e2 && { echo FAIL-2-exited0; R=1; } || grep -qi 'permission denied' /tmp/e2 && echo PASS-2 || { echo FAIL-2; cat /tmp/e2; R=1; }
echo "[3] sealed ws mount denied:"
timeout 20 docker -H $S run --rm -v /data/cybergym/stage3/r_engineer-ws/arvo_1065:/x:ro alpine ls /x 2>/tmp/e3 && { echo FAIL-3-exited0; R=1; } || grep -qi 'permission denied' /tmp/e3 && echo PASS-3 || { echo FAIL-3; cat /tmp/e3; R=1; }
echo "[4] no -fix image visible in rootless store:"
timeout 20 docker -H $S run --rm n132/arvo:50307-fix true 2>/tmp/e4 && { echo FAIL-4-ran; R=1; } || grep -qi 'not found\|Unable to find' /tmp/e4 && echo PASS-4 || { echo CHECK-4; cat /tmp/e4; }
exit $R
