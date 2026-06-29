# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000005
# Title:   The Photon operating system must display the Standard Mandatory DOD Notice and Consent Banner before granting local
# Severity:medium  CCI:CCI-000048,CCI-001384,CCI-001385,CCI-001386,CCI-001387,CCI-001388  NIST:AC-8 a,AC-8 c 1,AC-8 c 2,AC-8 c 3
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000005:
  file.managed:
    - name: /etc/issue
    - mode: 0644
    - user: root
    - group: root
    - source: 'salt://vcf9/files/PHTN-50-000005'
    - template: jinja

PHTN-50-000005_step2:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^#?\s*Banner\s'
    - repl: Banner /etc/issue
    - append_if_not_found: True
    - backup: False
