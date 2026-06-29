# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000008
# Title:   The ESX host must enable lockdown mode.
# Severity:medium  CCI:CCI-000054  NIST:AC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000008:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "$vmhost = Get-VMHost -Name <hostname> | Get-View"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VMHost | Select Name,@{N=\"Lockdown\";E={$_.Extensiondata.Config.LockdownMode}}); if($v){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000008_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000008: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
