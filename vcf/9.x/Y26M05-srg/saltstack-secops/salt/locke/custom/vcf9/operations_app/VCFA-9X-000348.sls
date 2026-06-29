# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000348
# Title:   VMware Cloud Foundation Operations must enforce the limit of three consecutive invalid logon attempts by a user dur
# Severity:medium  CCI:CCI-000044  NIST:AC-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000348_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000348: source STIG control is manual/Not-Applicable. Review per meta.'
