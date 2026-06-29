# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000111
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server must enable HTTP/2.
# Severity:medium  CCI:CCI-001310,CCI-002418  NIST:SC-8,SI-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFB-9X-000111:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFB-9X-000111'
    - template: jinja
