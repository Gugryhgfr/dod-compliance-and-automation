# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000213
# Title:   The Photon operating system must configure Secure Shell (SSH) to perform strict mode checking of home directory con
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000213:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^#?\s*StrictModes\s'
    - repl: StrictModes yes
    - append_if_not_found: True
    - backup: False
