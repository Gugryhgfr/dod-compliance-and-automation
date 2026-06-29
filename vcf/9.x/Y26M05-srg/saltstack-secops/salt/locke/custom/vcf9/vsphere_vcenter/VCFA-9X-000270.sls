# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000270
# Title:   The vCenter Server must disable accounts used for Integrated Windows Authentication (IWA).
# Severity:medium  CCI:CCI-003627  NIST:AC-2 (3) (a)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: inspec-audit-only

VCFA-9X-000270:
  cmd.run:
    - name: '/bin/false  # no automated remediation; see meta fix'
    - unless: '[ "$(Get-SsoPersonUser -Domain vsphere.local -Name "K/M" | Select-Object -ExpandProperty Disabled 2>/dev/null)" = "true" ]'
