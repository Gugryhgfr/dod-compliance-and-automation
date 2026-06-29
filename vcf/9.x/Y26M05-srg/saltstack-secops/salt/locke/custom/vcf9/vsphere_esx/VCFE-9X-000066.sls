# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000066
# Title:   The ESX host must set a timeout to automatically end idle shell sessions after fifteen minutes.
# Severity:medium  CCI:CCI-001133,CCI-002361  NIST:AC-12,SC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000066:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut); if(($v.Value -eq 900) -or ($v -eq 900)){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000066_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000066: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
