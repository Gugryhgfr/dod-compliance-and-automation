# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000266
# Title:   The Photon operating system must generate audit records for all account creations, modifications, disabling, and te
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000266:
  file.managed:
    - name: /etc/audit/rules.d/audit.STIG.rules
    - mode: 0640
    - user: root
    - group: root
    - source: 'salt://vcf9/files/PHTN-50-000266'
    - template: jinja
