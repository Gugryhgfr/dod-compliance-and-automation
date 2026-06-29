# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000245
# Title:   The Photon operating system must mount /tmp securely.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

PHTN-50-000245_manual:
  test.succeed_with_changes:
    - name: PHTN-50-000245 requires manual review. See meta global_description / remediation.
