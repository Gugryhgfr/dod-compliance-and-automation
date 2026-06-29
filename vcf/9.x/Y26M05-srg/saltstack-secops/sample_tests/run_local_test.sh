#!/usr/bin/env bash
# Assess (test=True) or remediate a single ported check with a local masterless minion.
# Usage: ./run_local_test.sh <check_ref> [assess|remediate]
#   e.g. ./run_local_test.sh locke.custom.vcf9.photon_5.PHTN-50-000007 assess
CHECK="$1"; MODE="${2:-assess}"
if [ "$MODE" = "remediate" ]; then TEST=""; else TEST="test=True"; fi
salt-call --local --file-root=./salt state.apply "$CHECK" $TEST
