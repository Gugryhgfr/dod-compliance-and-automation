# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000201
# Title:   The Photon operating system must enable Secure Shell (SSH) authentication logging.
# Severity:medium  CCI:CCI-000067  NIST:AC-17 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000201:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^#?\s*LogLevel\s'
    - repl: LogLevel INFO
    - append_if_not_found: True
    - backup: False
