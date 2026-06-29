# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000117
# Title:   The VMware Cloud Foundation vCenter Server must notify system administrators (SAs) and the information system secur
# Severity:medium  CCI:CCI-000015,CCI-001744  NIST:AC-2 (1),CM-3 (5)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFA-9X-000117:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "$amview = Get-View -Id ''AlarmManager-AlarmManager''"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq \"com.vmware.sso.PrincipalManagement\"} | Select Name,Enabled,@{N=\"EventTypeId\";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}); if($v){exit 0}else{exit 1}"'
{% else %}
VCFA-9X-000117_manual:
  test.succeed_with_changes:
    - name: 'API control VCFA-9X-000117: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
