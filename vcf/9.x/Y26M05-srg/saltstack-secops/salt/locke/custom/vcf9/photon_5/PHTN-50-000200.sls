# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000200
# Title:   The Photon operating system must configure the Secure Shell (SSH) SyslogFacility.
# Severity:medium  CCI:CCI-000067  NIST:AC-17 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000200:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^#?\s*SyslogFacility\s'
    - repl: SyslogFacility AUTHPRIV
    - append_if_not_found: True
    - backup: False
