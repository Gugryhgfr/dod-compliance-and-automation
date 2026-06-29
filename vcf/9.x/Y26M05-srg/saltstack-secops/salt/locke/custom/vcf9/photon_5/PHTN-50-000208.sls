# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000208
# Title:   The Photon operating system must configure Secure Shell (SSH) to disable user environment processing.
# Severity:high  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000208:
  file.replace:
    - name: /etc/ssh/sshd_config
    - pattern: '^#?\s*PermitUserEnvironment\s'
    - repl: PermitUserEnvironment no
    - append_if_not_found: True
    - backup: False
