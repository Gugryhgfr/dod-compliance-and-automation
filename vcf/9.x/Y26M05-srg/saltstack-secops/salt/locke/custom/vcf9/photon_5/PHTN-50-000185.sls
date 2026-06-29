# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000185
# Title:   The Photon operating system must enforce a delay of at least four seconds between logon prompts following a failed 
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000185:
  file.replace:
    - name: /etc/login.defs
    - pattern: '^\s*#?\s*FAIL_DELAY\s*.*$'
    - repl: FAIL_DELAY 4
    - append_if_not_found: True
    - backup: False
