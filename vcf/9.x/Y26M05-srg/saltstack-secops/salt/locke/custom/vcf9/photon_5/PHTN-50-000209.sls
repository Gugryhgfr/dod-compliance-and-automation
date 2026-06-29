# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000209
# Title:   The Photon operating system must create a home directory for all new local interactive user accounts.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000209:
  file.replace:
    - name: /etc/login.defs
    - pattern: '^#?\s*CREATE_HOME\s'
    - repl: CREATE_HOME yes
    - append_if_not_found: True
    - backup: False
