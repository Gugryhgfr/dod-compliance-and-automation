# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000048
# Title:   The ESX host must uniquely identify and must authenticate organizational users by using Active Directory.
# Severity:medium  CCI:CCI-000764,CCI-001682,CCI-003650,CCI-004045  NIST:AC-2 (2),AC-3 (13),IA-2,IA-2 (5)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000048:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain \"domain name\" -User \"username\" -Password \"password\""'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VMHost | Get-VMHostAuthentication); if($v){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000048_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000048: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
