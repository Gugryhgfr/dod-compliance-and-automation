# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000257
# Title:   The VMware Cloud Foundation vCenter Server must enforce SNMPv3 security features where SNMP is required.
# Severity:medium  CCI:CCI-001967  NIST:IA-3 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000257_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000257: source STIG control is manual/Not-Applicable. Review per meta.'
