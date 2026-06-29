# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000074
# Title:   The Photon operating system must reveal error messages only to authorized users.
# Severity:medium  CCI:CCI-001314  NIST:SI-11 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000074:
  file.replace:
    - name: /etc/rsyslog.conf
    - pattern: ^\$umask
    - repl: $umask 0037
    - append_if_not_found: True
    - backup: False
