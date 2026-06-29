# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000093
# Title:   The operating system must automatically terminate a user session after inactivity time-outs have expired.
# Severity:medium  CCI:CCI-002361  NIST:AC-12
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000093:
  file.managed:
    - name: /etc/profile.d/tmout.sh
    - mode: 0644
    - user: root
    - group: root
    - source: 'salt://vcf9/files/PHTN-50-000093'
    - template: jinja
