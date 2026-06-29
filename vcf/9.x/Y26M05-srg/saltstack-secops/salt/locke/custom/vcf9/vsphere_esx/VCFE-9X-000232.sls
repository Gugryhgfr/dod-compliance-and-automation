# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000232
# Title:   The ESX host must not be configured to override virtual machine (VM) configurations.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFE-9X-000232_manual:
  test.succeed_with_changes:
    - name: 'VCFE-9X-000232: source STIG control is manual/Not-Applicable. Review per meta.'
