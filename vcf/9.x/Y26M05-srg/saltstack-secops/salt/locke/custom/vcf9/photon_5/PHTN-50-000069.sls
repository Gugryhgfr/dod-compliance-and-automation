# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000069
# Title:   The Photon operating system must terminate idle Secure Shell (SSH) sessions after 15 minutes.
# Severity:medium  CCI:CCI-001133,CCI-002891  NIST:MA-4 (7),SC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000069:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^#?\s*ClientAliveInterval\s'
    - repl: ClientAliveInterval 900
    - append_if_not_found: True
    - backup: False
