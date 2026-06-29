# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000105
# Title:   The VMware Cloud Foundation vCenter Server must manage excess capacity, bandwidth, or other redundancy to limit the
# Severity:medium  CCI:CCI-001095,CCI-002385  NIST:SC-5 (2),SC-5 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFA-9X-000105:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Write-Output ''manual remediation required''"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VDSwitch | select Name,@{N=\"NIOC Enabled\";E={$_.ExtensionData.config.NetworkResourceManagementEnabled}}); if($v){exit 0}else{exit 1}"'
{% else %}
VCFA-9X-000105_manual:
  test.succeed_with_changes:
    - name: 'API control VCFA-9X-000105: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
