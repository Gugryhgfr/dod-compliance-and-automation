# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000107
# Title:   The Photon operating system must audit the execution of privileged functions.
# Severity:medium  CCI:CCI-000172,CCI-001404,CCI-002234,CCI-004188  NIST:AC-2 (4),AC-6 (9),AU-12 c,MA-3 (5)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000107:
  file.managed:
    - name: /etc/audit/rules.d/audit.STIG.rules
    - mode: 0640
    - user: root
    - group: root
    - source: 'salt://vcf9/files/PHTN-50-000107'
    - template: jinja
