# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000024
# Title:   VMware Cloud Foundation Operations for Networks must enable the generation of audit records with sufficient informa
# Severity:medium  CCI:CCI-000169  NIST:AU-12 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000024_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000024: source STIG control is manual/Not-Applicable. Review per meta.'
