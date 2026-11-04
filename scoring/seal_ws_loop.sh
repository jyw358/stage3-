#!/bin/bash
# phase-1 ws sealing loop: seal completed stage3 ws every 10 min. Root only.
while :; do
  python3 /root/seal_ws_once.py
  sleep 600
done
