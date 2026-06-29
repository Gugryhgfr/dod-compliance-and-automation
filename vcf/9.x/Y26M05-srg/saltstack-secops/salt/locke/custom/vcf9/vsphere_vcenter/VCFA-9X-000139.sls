# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000139
# Title:   The VMware Cloud Foundation vCenter Server must automatically lock the account until the locked account is released
# Severity:medium  CCI:CCI-002238  NIST:AC-7 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFA-9X-000139_manual:
  test.succeed_with_changes:
    - name: VCFA-9X-000139 requires manual review. See meta global_description / remediation.
