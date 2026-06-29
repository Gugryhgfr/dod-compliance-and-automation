# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000203
# Title:   The Photon operating system must terminate idle Secure Shell (SSH) sessions.
# Severity:medium  CCI:CCI-001133  NIST:SC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000203:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^\s*#?\s*ClientAliveCountMax\s+.*$'
    - repl: ClientAliveCountMax 0
    - append_if_not_found: True
    - backup: False
