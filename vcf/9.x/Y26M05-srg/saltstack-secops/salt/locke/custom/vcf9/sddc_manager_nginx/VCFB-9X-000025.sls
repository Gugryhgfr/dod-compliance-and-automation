# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000025
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server must protect the .htpasswd file from unauthorized access.
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFB-9X-000025:
  file.managed:
    - name: /etc/nginx/.htpasswd
    - replace: False
    - create: True
    - mode: 0640
    - user: root
    - group: nginx
