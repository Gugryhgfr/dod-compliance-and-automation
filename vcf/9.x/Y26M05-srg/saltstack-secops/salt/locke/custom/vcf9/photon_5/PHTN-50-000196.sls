# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000196
# Title:   The Photon operating system must persist lockouts between system reboots.
# Severity:medium  CCI:CCI-000044  NIST:AC-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000196:
  file.replace:
    - name: /etc/security/faillock.conf
    - pattern: '^\s*#?\s*dir\s*=\s*.*$'
    - repl: dir = /var/log/faillock
    - append_if_not_found: True
    - backup: False

PHTN-50-000196_step2:
  file.directory:
    - name: /var/log/faillock
    - mode: 0750
    - user: root
    - group: root
