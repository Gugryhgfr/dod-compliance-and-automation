# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000347
# Title:   VMware Cloud Foundation Operations must display the Standard Mandatory DOD Notice and Consent Banner before logon.
# Severity:medium  CCI:CCI-000048  NIST:AC-8 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000347_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000347: source STIG control is manual/Not-Applicable. Review per meta.'
