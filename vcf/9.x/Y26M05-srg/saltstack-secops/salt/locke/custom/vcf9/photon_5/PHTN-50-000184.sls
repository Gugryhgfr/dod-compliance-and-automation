# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000184
# Title:   The Photon operating system must prevent the use of dictionary words for passwords.
# Severity:medium  CCI:CCI-000366,CCI-004061  NIST:CM-6 b,IA-5 (1) (b)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000184:
  file.replace:
    - name: /etc/security/pwquality.conf
    - pattern: '^\s*#?\s*dictcheck\s*=\s*.*$'
    - repl: dictcheck = 1
    - append_if_not_found: True
    - backup: False

PHTN-50-000184_step2:
  file.replace:
    - name: /etc/pam.d/system-password
    - pattern: '^(\s*password\s+\S+\s+pam_pwquality\.so\b)(.*)$'
    - repl: \1 dictcheck=1
    - append_if_not_found: False
    - backup: False
