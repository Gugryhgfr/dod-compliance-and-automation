# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000021
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must off-load log records onto a different system or medi
# Severity:medium  CCI:CCI-000139,CCI-001348,CCI-001851,CCI-003821,CCI-003831,CCI-003938  NIST:AU-4 (1),AU-5 a,AU-6 (4),AU-9 (2),AU-9 b,CM-5 (1) (b)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000021:
  file.managed:
    - name: /etc/vmware-syslog/vmware-services-applmgmt.conf
    - mode: 0644
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFM-9X-000021'
    - template: jinja
