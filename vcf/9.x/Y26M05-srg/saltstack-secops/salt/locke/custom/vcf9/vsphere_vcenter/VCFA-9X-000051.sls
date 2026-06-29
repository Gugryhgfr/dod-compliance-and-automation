# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000051
# Title:   VMware Cloud Foundation vCenter Server client plugins must be verified.
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000051_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000051: source STIG control is manual/Not-Applicable. Review per meta.'
