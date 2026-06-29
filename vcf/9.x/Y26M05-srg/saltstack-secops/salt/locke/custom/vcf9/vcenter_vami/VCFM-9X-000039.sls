# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000039
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must restrict access to the web server's private key.
# Severity:medium  CCI:CCI-000186,CCI-004910  NIST:IA-5 (2) (a) (1),SC-28 (3)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000039:
  file.managed:
    - name: /etc/applmgmt/appliance/server.pem
    - replace: False
    - create: True
    - mode: 0600
    - user: root
    - group: root
