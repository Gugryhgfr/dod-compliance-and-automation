# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000325
# Title:   The VMware Cloud Foundation vCenter Server must set the distributed port group Promiscuous Mode policy to "Reject".
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFA-9X-000325:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Get-VDSecurityPolicy); if($v){exit 0}else{exit 1}"'
{% else %}
VCFA-9X-000325_manual:
  test.succeed_with_changes:
    - name: 'API control VCFA-9X-000325: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
