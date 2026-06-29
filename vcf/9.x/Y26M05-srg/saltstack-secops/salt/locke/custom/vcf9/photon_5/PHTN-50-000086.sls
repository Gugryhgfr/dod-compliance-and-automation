# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000086
# Title:   The Photon operating system must enforce password complexity by requiring that at least one special character be us
# Severity:medium  CCI:CCI-004066  NIST:IA-5 (1) (h)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000086:
  file.replace:
    - name: /etc/security/pwquality.conf
    - pattern: '^\s*#?\s*ocredit\s*=\s*.*$'
    - repl: ocredit = -1
    - append_if_not_found: True
    - backup: False

PHTN-50-000086_step2:
  file.replace:
    - name: /etc/pam.d/system-password
    - pattern: '^(\s*password\s+\S+\s+pam_pwquality\.so\b)(.*)$'
    - repl: \1 ocredit=-1
    - append_if_not_found: False
    - backup: False
