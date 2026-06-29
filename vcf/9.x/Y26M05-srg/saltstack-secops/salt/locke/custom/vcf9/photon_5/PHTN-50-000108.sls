# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000108
# Title:   The Photon operating system must automatically lock an account until the locked account is released by an administr
# Severity:medium  CCI:CCI-002238  NIST:AC-7 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000108:
  file.replace:
    - name: /etc/security/faillock.conf
    - pattern: '^\s*#?\s*unlock_time\s*=\s*.*$'
    - repl: unlock_time = 0
    - append_if_not_found: True
    - backup: False
