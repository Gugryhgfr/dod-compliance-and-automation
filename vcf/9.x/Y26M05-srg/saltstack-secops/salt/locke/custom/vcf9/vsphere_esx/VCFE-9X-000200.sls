# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000200
# Title:   The ESX host must automatically stop shell services after ten minutes.
# Severity:medium  CCI:CCI-001133  NIST:SC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000200:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut); if(($v.Value -eq 600) -or ($v -eq 600)){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000200_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000200: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
