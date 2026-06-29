# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000021
# Title:   The Photon operating system must alert the ISSO and SA in the event of an audit processing failure.
# Severity:medium  CCI:CCI-000139,CCI-001858  NIST:AU-5 (2),AU-5 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000021:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*disk_full_action\s*=\s*.*$'
    - repl: disk_full_action = SYSLOG
    - append_if_not_found: True
    - backup: False

PHTN-50-000021_step2:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*disk_error_action\s*=\s*.*$'
    - repl: disk_error_action = SYSLOG
    - append_if_not_found: True
    - backup: False

PHTN-50-000021_step3:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*admin_space_left_action\s*=\s*.*$'
    - repl: admin_space_left_action = SYSLOG
    - append_if_not_found: True
    - backup: False
