# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFE-9X-000006
# Title:   The ESX host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system
# Severity:medium  CCI:CCI-000048,CCI-000050  NIST:AC-8 a,AC-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFE-9X-000006:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value \"<Banner text above>\""'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage); if($v){exit 0}else{exit 1}"'
{% else %}
VCFE-9X-000006_manual:
  test.succeed_with_changes:
    - name: 'API control VCFE-9X-000006: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
