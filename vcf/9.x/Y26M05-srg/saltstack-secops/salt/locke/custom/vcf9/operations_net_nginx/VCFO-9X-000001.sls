# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFO-9X-000001
# Title:   The VMware Cloud Foundation Operations for Networks Platform NGINX server must limit the number of concurrent conne
# Severity:medium  CCI:CCI-000054  NIST:AC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFO-9X-000001:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFO-9X-000001'
    - template: jinja
