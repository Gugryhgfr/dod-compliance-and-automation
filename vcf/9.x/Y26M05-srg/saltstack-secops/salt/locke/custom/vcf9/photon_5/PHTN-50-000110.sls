# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000110
# Title:   The Photon operating system must allocate audit record storage capacity to store audit records when audit records a
# Severity:low  CCI:CCI-001849  NIST:AU-4
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000110:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*num_logs\s*=\s*.*$'
    - repl: num_logs = 5
    - append_if_not_found: True
    - backup: False

PHTN-50-000110_step2:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*max_log_file_action\s*=\s*.*$'
    - repl: max_log_file_action = ROTATE
    - append_if_not_found: True
    - backup: False
