# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000028
# Title:   The VMware Cloud Foundation vCenter Server must produce audit records containing information to establish what type
# Severity:medium  CCI:CCI-000130,CCI-000132,CCI-000133,CCI-000134,CCI-001487  NIST:AU-3 a,AU-3 c,AU-3 d,AU-3 e,AU-3 f
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFA-9X-000028:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level | Set-AdvancedSetting -Value info"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-AdvancedSetting -Entity <vcenter server name> -Name config.log.level and verify it is set to \"info\".); if(($v.Value -eq ''info'') -or ($v -eq ''info'')){exit 0}else{exit 1}"'
{% else %}
VCFA-9X-000028_manual:
  test.succeed_with_changes:
    - name: 'API control VCFA-9X-000028: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
