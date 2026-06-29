# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000104
# Title:   VMware Cloud Foundation Automation must restrict the ability of individuals to use information systems to launch de
# Severity:medium  CCI:CCI-001094  NIST:SC-5 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000104_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000104: source STIG control is manual/Not-Applicable. Review per meta.'
