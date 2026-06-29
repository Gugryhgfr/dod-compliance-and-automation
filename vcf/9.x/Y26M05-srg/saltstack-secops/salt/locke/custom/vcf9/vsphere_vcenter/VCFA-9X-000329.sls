# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000329
# Title:   The VMware Cloud Foundation vCenter Server must be configured to send events to a central log server.
# Severity:medium  CCI:CCI-001851  NIST:AU-4 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFA-9X-000329:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-AdvancedSetting -Entity <vcenter server name> -Name vpxd.event.syslog.enabled | Set-AdvancedSetting -Value true"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-AdvancedSetting -Entity <vcenter server name> -Name vpxd.event.syslog.enabled); if(($v.Value -eq $true) -or ($v -eq $true)){exit 0}else{exit 1}"'
{% else %}
VCFA-9X-000329_manual:
  test.succeed_with_changes:
    - name: 'API control VCFA-9X-000329: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
