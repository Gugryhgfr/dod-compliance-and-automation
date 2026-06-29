# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFV-9X-000206
# Title:   Virtual machines (VMs) must be configured to lock when the last console connection is closed.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFV-9X-000206:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.guest.desktop.autolock | Set-AdvancedSetting -Value true"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VM \"VM Name\" | Get-AdvancedSetting -Name tools.guest.desktop.autolock); if(($v.Value -eq $true) -or ($v -eq $true)){exit 0}else{exit 1}"'
{% else %}
VCFV-9X-000206_manual:
  test.succeed_with_changes:
    - name: 'API control VCFV-9X-000206: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
