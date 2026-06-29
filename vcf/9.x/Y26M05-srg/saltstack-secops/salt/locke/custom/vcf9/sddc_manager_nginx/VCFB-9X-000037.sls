# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000037
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server must be configured to use a specified IP address and port.
# Severity:medium  CCI:CCI-000382,CCI-001762  NIST:CM-7 (1) (b),CM-7 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFB-9X-000037:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFB-9X-000037'
    - template: jinja
