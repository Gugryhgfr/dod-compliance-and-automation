# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000353
# Title:   VMware Cloud Foundation Operations must enable firewall hardening.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000353_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000353: source STIG control is manual/Not-Applicable. Review per meta.'
