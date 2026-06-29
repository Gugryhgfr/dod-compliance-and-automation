# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000039
# Title:   The operating system must store only encrypted representations of passwords.
# Severity:high  CCI:CCI-004062  NIST:IA-5 (1) (d)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000039:
  file.replace:
    - name: /etc/login.defs
    - pattern: '^#?\s*ENCRYPT_METHOD\s'
    - repl: ENCRYPT_METHOD SHA512
    - append_if_not_found: True
    - backup: False
