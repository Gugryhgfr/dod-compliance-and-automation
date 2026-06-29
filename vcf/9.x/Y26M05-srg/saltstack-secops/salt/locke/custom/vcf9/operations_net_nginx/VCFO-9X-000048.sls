# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFO-9X-000048
# Title:   The VMware Cloud Foundation Operations for Networks Platform NGINX server must secure session cookies exchanged bet
# Severity:medium  CCI:CCI-001664,CCI-002418  NIST:SC-23 (3),SC-8
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFO-9X-000048:
  file.managed:
    - name: /etc/nginx/sites-available/vnera
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFO-9X-000048'
    - template: jinja

VCFO-9X-000048_step2:
  file.managed:
    - name: /etc/nginx/sites-available/vnera
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFO-9X-000048'
    - template: jinja
