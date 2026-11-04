#!/bin/bash
# stage-1/2 switch: docker context -> rootless, then verify; gpasswd done separately as root
export XDG_RUNTIME_DIR=/run/user/1000
docker context create rootless --docker host=unix:///data/cybergym-rootless/docker.sock 2>/dev/null || docker context update rootless --docker host=unix:///data/cybergym-rootless/docker.sock
docker context use rootless
echo "--- context now:"; docker context show
echo "--- smoke via context:"; timeout 20 docker run --rm alpine echo CONTEXT-OK || echo CONTEXT-FAIL
