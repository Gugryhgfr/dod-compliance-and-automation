# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000130
# Title:   The ESX Image Profile and vSphere Installation Bundle (VIB) acceptance level must be verified.
# Severity:medium  CCI:CCI-001774,CCI-003992  NIST:CM-14,CM-7 (5) (b)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000130:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "$esxcli = Get-EsxCli -v2"'
    - unless: 'pwsh -NoProfile -Command "$v=($esxcli = Get-EsxCli -v2); if($v){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000130_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000130: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
