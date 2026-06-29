# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000133
# Title:   The Photon operating system must require users to reauthenticate for privilege escalation.
# Severity:medium  CCI:CCI-002038  NIST:IA-11
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

PHTN-50-000133_manual:
  test.succeed_with_changes:
    - name: PHTN-50-000133 requires manual review. See meta global_description / remediation.
