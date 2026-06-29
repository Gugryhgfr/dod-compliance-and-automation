# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000376
# Title:   VMware Cloud Foundation Operations for Networks must terminate sessions after 15 minutes of inactivity.
# Severity:medium  CCI:CCI-001133  NIST:SC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000376_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000376: source STIG control is manual/Not-Applicable. Review per meta.'
