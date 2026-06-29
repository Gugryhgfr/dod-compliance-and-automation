# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFO-9X-000090
# Title:   The VMware Cloud Foundation Operations for Networks Platform NGINX server must maintain the confidentiality of cont
# Severity:medium  CCI:CCI-002418,CCI-002420,CCI-002422  NIST:SC-8,SC-8 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFO-9X-000090:
  file.managed:
    - name: /etc/nginx/sites-available/vnera
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFO-9X-000090'
    - template: jinja

VCFO-9X-000090_step2:
  file.managed:
    - name: /etc/nginx/sites-available/vnera
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFO-9X-000090'
    - template: jinja
