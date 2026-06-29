# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000003
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server must enable SSL on external server contexts.
# Severity:medium  CCI:CCI-000068,CCI-000197,CCI-002418  NIST:AC-17 (2),IA-5 (1) (c),SC-8
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFB-9X-000003:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFB-9X-000003'
    - template: jinja
