# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000161
# Title:   The Photon operating system must remove all software components after updated versions have been installed.
# Severity:medium  CCI:CCI-002617  NIST:SI-2 (6)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000161:
  file.replace:
    - name: /etc/tdnf/tdnf.conf
    - pattern: '^\s*#?\s*clean_requirements_on_remove\s*=\s*.*$'
    - repl: clean_requirements_on_remove=1
    - append_if_not_found: True
    - backup: False
