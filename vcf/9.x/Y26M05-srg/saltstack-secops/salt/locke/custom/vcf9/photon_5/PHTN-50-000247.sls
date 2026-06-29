# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000247
# Title:   The Photon operating system must not allow empty passwords.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000247:
  file.replace:
    - name: /etc/pam.d/system-password
    - pattern: '^(password.*pam_unix\.so.*)(\snullok)(.*)'
    - repl: \1\3
    - backup: False

PHTN-50-000247_step2:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(auth.*pam_unix\.so.*)(\snullok)(.*)'
    - repl: \1\3
    - backup: False
