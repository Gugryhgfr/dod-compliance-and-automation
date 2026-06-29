# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000239
# Title:   The Photon operating system must implement only approved Message Authentication Codes (MACs) to protect the integri
# Severity:high  CCI:CCI-001453  NIST:AC-17 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000239:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^#?\s*MACs\s'
    - repl: 'MACs hmac-sha2-512,hmac-sha2-256'
    - append_if_not_found: True
    - backup: False
