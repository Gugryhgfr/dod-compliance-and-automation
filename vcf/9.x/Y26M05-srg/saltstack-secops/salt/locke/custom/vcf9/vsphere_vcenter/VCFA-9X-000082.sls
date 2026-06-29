# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000082
# Title:   The VMware Cloud Foundation vCenter Server must terminate sessions after 15 minutes of inactivity.
# Severity:medium  CCI:CCI-000366,CCI-001133,CCI-002038,CCI-002361,CCI-005162  NIST:AC-12,CM-6 b,IA-11,SC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000082_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000082: source STIG control is manual/Not-Applicable. Review per meta.'
