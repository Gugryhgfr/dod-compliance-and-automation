# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000092
# Title:   The Photon operating system must use cryptographic mechanisms to protect the integrity of audit tools.
# Severity:high  CCI:CCI-001496  NIST:AU-9 (3)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

PHTN-50-000092_manual:
  test.succeed_with_changes:
    - name: PHTN-50-000092 requires manual review. See meta global_description / remediation.
