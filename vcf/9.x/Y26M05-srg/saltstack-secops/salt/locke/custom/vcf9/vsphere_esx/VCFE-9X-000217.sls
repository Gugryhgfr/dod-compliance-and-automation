# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000217
# Title:   The ESX host must configure the firewall to restrict access to services running on the host.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000217:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "$esxcli = Get-EsxCli -v2"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VMHost | Get-VMHostFirewallException | Where {($_.Enabled -eq $true) -and ($_.ExtensionData.IpListUserConfigurable -eq $true)} | Select Name,Enabled,@{N=\"AllIPEnabled\";E={$_.ExtensionData.AllowedHosts.AllIP}},@{N=\"AllIPUserConfigurable\";E={$_.ExtensionData.IpListUserConfigurable}}); if($v){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000217_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000217: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
