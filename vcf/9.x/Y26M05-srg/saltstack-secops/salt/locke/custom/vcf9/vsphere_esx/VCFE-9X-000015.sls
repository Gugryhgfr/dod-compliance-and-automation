# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000015
# Title:   The ESX host must produce audit records containing information to establish what type of events occurred.
# Severity:medium  CCI:CCI-000130,CCI-000171  NIST:AU-12 b,AU-3 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: inspec-audit-only

VCFE-9X-000015:
  cmd.run:
    - name: '/bin/false  # no automated remediation; see meta fix'
    - unless: '[ "$(Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name 2>/dev/null)" = "info" ]'
