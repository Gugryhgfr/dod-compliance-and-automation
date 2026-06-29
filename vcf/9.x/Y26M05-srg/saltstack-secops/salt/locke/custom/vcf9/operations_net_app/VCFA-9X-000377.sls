# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000377
# Title:   VMware Cloud Foundation Operations for Networks must disable automatic certificate validation for data sources.
# Severity:medium  CCI:CCI-000185  NIST:IA-5 (2) (b) (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000377_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000377: source STIG control is manual/Not-Applicable. Review per meta.'
