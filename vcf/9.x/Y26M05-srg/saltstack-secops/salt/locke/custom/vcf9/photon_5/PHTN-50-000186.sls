# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000186
# Title:   The Photon operating system must ensure audit events are flushed to disk at proper intervals.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000186:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*flush\s*=\s*.*$'
    - repl: flush = INCREMENTAL_ASYNC
    - append_if_not_found: True
    - backup: False

PHTN-50-000186_step2:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*freq\s*=\s*.*$'
    - repl: freq = 50
    - append_if_not_found: True
    - backup: False
