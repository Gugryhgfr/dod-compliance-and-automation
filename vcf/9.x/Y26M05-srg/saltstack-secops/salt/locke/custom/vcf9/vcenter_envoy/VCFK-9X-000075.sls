# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFK-9X-000075
# Title:   The VMware Cloud Foundation vCenter Envoy service log files must be sent to a central log server.
# Severity:medium  CCI:CCI-001348,CCI-001851  NIST:AU-4 (1),AU-9 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFK-9X-000075:
  file.managed:
    - name: /etc/vmware-syslog/vmware-services-envoy.conf
    - mode: 0644
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFK-9X-000075'
    - template: jinja
