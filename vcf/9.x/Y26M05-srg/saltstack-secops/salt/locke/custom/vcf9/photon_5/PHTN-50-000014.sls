# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000014
# Title:   The Photon operating system must configure auditd to log to disk.
# Severity:medium  CCI:CCI-000130  NIST:AU-3 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000014:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*write_log\s*=\s*.*$'
    - repl: write_logs = yes
    - append_if_not_found: True
    - backup: False
