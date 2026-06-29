# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000385
# Title:   VMware Cloud Foundation Operations HCX must include only approved trust anchors in trust stores or certificate stor
# Severity:medium  CCI:CCI-004909  NIST:SC-17 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000385_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000385: source STIG control is manual/Not-Applicable. Review per meta.'
