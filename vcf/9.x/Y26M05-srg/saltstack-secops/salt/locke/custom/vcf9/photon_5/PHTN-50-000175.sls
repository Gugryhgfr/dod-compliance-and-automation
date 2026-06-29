# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000175
# Title:   The Photon operating system must be configured to audit the loading and unloading of dynamic kernel modules.
# Severity:medium  CCI:CCI-000172  NIST:AU-12 c
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000175:
  file.managed:
    - name: /etc/audit/rules.d/audit.STIG.rules
    - mode: 0640
    - user: root
    - group: root
    - source: 'salt://vcf9/files/PHTN-50-000175'
    - template: jinja
