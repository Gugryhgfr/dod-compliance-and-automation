# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000041
# Title:   The Photon operating system must enforce one day as the minimum password lifetime.
# Severity:medium  CCI:CCI-004066  NIST:IA-5 (1) (h)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000041:
  file.replace:
    - name: /etc/login.defs
    - pattern: '^\s*#?\s*PASS_MIN_DAYS\s*.*$'
    - repl: PASS_MIN_DAYS 1
    - append_if_not_found: True
    - backup: False
