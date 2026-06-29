# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000312
# Title:   The VMware Cloud Foundation vCenter Server must include only approved trust anchors in trust stores or certificate 
# Severity:medium  CCI:CCI-004909  NIST:SC-17 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000312_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000312: source STIG control is manual/Not-Applicable. Review per meta.'
