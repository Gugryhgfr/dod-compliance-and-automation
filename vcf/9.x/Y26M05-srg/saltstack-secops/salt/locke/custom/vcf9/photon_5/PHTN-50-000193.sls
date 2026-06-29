# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000193
# Title:   The Photon operating system must prevent leaking information of the existence of a user account.
# Severity:medium  CCI:CCI-000044  NIST:AC-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000193:
  file.replace:
    - name: /etc/security/faillock.conf
    - pattern: '^#?\s*silent.*$'
    - repl: silent
    - append_if_not_found: True
    - backup: False
