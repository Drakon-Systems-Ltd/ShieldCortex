#!/usr/bin/env bash
# Run the full #853 Plane A cancel / once-only matrix (cases in parallel; each case <= 60 s).
HERE="$(cd "$(dirname "$0")" && pwd)"
#                         CASE hookTO hold mode        onSig action     at
POST_WAIT=5  "$HERE/run-case.sh" O1 40 15 allow      exit  none       0 &
POST_WAIT=5  "$HERE/run-case.sh" O2 40 15 allow      exit  none       0 &
POST_WAIT=5  "$HERE/run-case.sh" O3 40 8  cancelfile exit  none       0 &
POST_WAIT=28 "$HERE/run-case.sh" X1 50 30 allow      exit  TERM       6 &
POST_WAIT=28 "$HERE/run-case.sh" X2 50 30 allow      exit  INT        6 &
POST_WAIT=28 "$HERE/run-case.sh" X3 50 30 allow      allow TERM       6 &
POST_WAIT=28 "$HERE/run-case.sh" X4 50 30 cancelfile exit  cancelfile 6 &
wait
