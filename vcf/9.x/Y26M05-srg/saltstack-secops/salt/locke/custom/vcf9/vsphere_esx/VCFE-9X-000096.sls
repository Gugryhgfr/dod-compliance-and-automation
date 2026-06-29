# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000096
# Title:   The ESX host must disable remote access to the information system by disabling Secure Shell (SSH).
# Severity:medium  CCI:CCI-002314,CCI-002322  NIST:AC-17 (1),AC-17 (9)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: inspec-audit-only

VCFE-9X-000096:
  cmd.run:
    - name: '/bin/false  # no automated remediation; see meta fix'
    - unless: '[ "$(Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name 2>/dev/null)" = "off" ]'
