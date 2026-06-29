# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000040
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server private keys must be protected from unauthorized access.
# Severity:medium  CCI:CCI-000186,CCI-004910  NIST:IA-5 (2) (a) (1),SC-28 (3)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFB-9X-000040:
  file.managed:
    - name: /etc/ssl/private/vcf_https.key
    - replace: False
    - create: True
    - mode: 0640
    - user: root
    - group: root
