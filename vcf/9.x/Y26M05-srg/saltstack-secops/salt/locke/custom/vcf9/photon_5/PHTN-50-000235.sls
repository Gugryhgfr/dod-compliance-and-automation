# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000235
# Title:   The Photon operating system must enforce password complexity on the root account.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000235:
  file.replace:
    - name: /etc/security/pwquality.conf
    - pattern: '^#?\s*enforce_for_root\s'
    - repl: enforce_for_root
    - append_if_not_found: True
    - backup: False

PHTN-50-000235_step2:
  file.replace:
    - name: /etc/pam.d/system-password
    - pattern: '^(\s*password\s+\S+\s+pam_pwquality\.so\b)(.*)$'
    - repl: \1 enforce_for_root
    - append_if_not_found: False
    - backup: False
