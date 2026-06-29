# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000082
# Title:   The ESX host must enable Secure Boot enforcement for configuration encryption.
# Severity:medium  CCI:CCI-001494,CCI-001495,CCI-002696,CCI-002699  NIST:AU-9,SI-6 a,SI-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: inspec-audit-only

VCFE-9X-000082:
  cmd.run:
    - name: '/bin/false  # no automated remediation; see meta fix'
    - unless: '[ "$(Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name 2>/dev/null)" = "true" ]'
