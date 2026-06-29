# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000059
# Title:   The Photon operating system must use mechanisms meeting the requirements of applicable federal laws, Executive orde
# Severity:medium  CCI:CCI-000803  NIST:IA-7
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000059:
  file.replace:
    - name: /etc/pam.d/system-password
    - pattern: '^(\s*password\s+\S+\s+pam_unix\.so\b)(.*)$'
    - repl: '\1 [''sha512'']'
    - append_if_not_found: False
    - backup: False
