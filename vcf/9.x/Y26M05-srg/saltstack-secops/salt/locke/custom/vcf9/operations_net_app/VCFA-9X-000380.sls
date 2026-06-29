# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000380
# Title:   VMware Cloud Foundation Operations for Networks assigned roles and permissions must be verified.
# Severity:medium  CCI:CCI-001082  NIST:SC-2
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000380_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000380: source STIG control is manual/Not-Applicable. Review per meta.'
