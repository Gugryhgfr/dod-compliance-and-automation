# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000012
# Title:   The Photon operating system must monitor remote access logins.
# Severity:medium  CCI:CCI-000067  NIST:AC-17 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000012:
  file.replace:
    - name: /etc/rsyslog.conf
    - pattern: '^#?\s*(^auth.*|^authpriv.*|^daemon.*)'
    - repl: 'auth.*;authpriv.*;daemon.* /var/log/messages'
    - append_if_not_found: True
    - backup: False
