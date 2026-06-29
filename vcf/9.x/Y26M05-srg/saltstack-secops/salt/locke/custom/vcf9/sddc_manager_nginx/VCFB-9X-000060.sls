# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000060
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server must restrict the ability of users to launch Denial of Servic
# Severity:medium  CCI:CCI-001094,CCI-002385  NIST:SC-5 (1),SC-5 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFB-9X-000060:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFB-9X-000060'
    - template: jinja
