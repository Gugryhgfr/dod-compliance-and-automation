# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000018
# Title:   The VMware Cloud Foundation vCenter Server must display the Standard Mandatory DOD Notice and Consent Banner before
# Severity:medium  CCI:CCI-000048,CCI-000050,CCI-001384,CCI-001385,CCI-001386,CCI-001387,CCI-001388  NIST:AC-8 a,AC-8 b,AC-8 c 1,AC-8 c 2,AC-8 c 3
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000018_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000018: source STIG control is manual/Not-Applicable. Review per meta.'
