# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000079
# Title:   The Photon operating system must implement only approved ciphers to protect the integrity of remote access sessions
# Severity:high  CCI:CCI-001453  NIST:AC-17 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000079:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^#?\s*Ciphers\s'
    - repl: 'Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
    - append_if_not_found: True
    - backup: False
