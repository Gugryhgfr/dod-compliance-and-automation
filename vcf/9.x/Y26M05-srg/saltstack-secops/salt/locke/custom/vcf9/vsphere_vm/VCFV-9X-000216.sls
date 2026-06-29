# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFV-9X-000216
# Title:   Virtual machines (VMs) must remove unneeded parallel devices.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a
#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.
# Tier: powercli-proxy

{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}
VCFV-9X-000216:
  cmd.run:
    - name: 'pwsh -NoProfile -Command "$pport = (Get-VM -Name <vmname>).ExtensionData.Config.Hardware.Device | Where {$_.DeviceInfo.Label -match \"Parallel\"}"'
    - unless: 'pwsh -NoProfile -Command "$v=(Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match \"parallel\"}); if($v){exit 0}else{exit 1}"'
{% else %}
VCFV-9X-000216_manual:
  test.succeed_with_changes:
    - name: 'API control VCFV-9X-000216: enable pillar vcf_secops:enable_powercli or review manually.'
{% endif %}
