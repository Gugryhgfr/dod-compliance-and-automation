# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000047
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server must invalidate session identifiers upon hosted application u
# Severity:medium  CCI:CCI-001185,CCI-002361  NIST:AC-12,SC-23 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFB-9X-000047:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFB-9X-000047'
    - template: jinja
