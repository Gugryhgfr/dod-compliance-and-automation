# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000204
# Title:   The ESX host must protect the confidentiality and integrity of transmitted information by isolating IP-based storag
# Severity:medium  CCI:CCI-002418  NIST:SC-8
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFE-9X-000204_manual:
  test.succeed_with_changes:
    - name: VCFE-9X-000204 requires manual review. See meta global_description / remediation.
