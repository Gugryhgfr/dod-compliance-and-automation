# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000112
# Title:   The Photon operating system must immediately notify the SA and ISSO when allocated audit record storage volume reac
# Severity:low  CCI:CCI-001855  NIST:AU-5 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000112:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*space_left\s*=\s*.*$'
    - repl: 'space_left = 25%'
    - append_if_not_found: True
    - backup: False

PHTN-50-000112_step2:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*space_left_action\s*=\s*.*$'
    - repl: space_left_action = SYSLOG
    - append_if_not_found: True
    - backup: False
