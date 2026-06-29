# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000215
# Title:   The ESX host must disable Simple Network Management Protocol (SNMP) v1 and v2c.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: inspec-audit-only

VCFE-9X-000215:
  cmd.run:
    - name: '/bin/false  # no automated remediation; see meta fix'
    - unless: '[ "$(Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name 2>/dev/null)" = "false" ]'
