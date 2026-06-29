# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000366
# Title:   VMware Cloud Foundation Operations must compare internal information system clocks with an authoritative time serve
# Severity:medium  CCI:CCI-004923  NIST:SC-45 (1) (a)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000366_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000366: source STIG control is manual/Not-Applicable. Review per meta.'
