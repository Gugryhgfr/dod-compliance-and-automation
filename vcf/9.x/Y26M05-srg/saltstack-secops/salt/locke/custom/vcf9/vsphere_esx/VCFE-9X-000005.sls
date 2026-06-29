# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000005
# Title:   The ESX host must enforce the limit of three consecutive invalid logon attempts by a user.
# Severity:medium  CCI:CCI-000044  NIST:AC-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000005:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures); if(($v.Value -eq 3) -or ($v -eq 3)){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000005_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000005: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
