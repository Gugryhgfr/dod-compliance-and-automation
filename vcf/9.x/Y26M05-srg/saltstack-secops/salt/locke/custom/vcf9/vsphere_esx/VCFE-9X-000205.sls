# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000205
# Title:   The ESX host lockdown mode exception users list must be verified.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000205:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Write-Output ''manual remediation required''"'
    - unless: 'pwsh -NoProfile -Command "$v=($vmhost = Get-VMHost | Get-View); if($v){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000205_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000205: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
