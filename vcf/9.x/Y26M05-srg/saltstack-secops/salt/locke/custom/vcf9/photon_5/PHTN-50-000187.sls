# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000187
# Title:   The Photon operating system must define default permissions for all authenticated users in such a way that the user
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000187:
  file.replace:
    - name: /etc/login.defs
    - pattern: '^#?\s*UMASK\s'
    - repl: UMASK 077
    - append_if_not_found: True
    - backup: False
