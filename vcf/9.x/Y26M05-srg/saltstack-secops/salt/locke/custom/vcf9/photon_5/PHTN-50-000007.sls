# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000007
# Title:   The Photon operating system must limit the number of concurrent sessions to ten for all accounts and/or account typ
# Severity:low  CCI:CCI-000054  NIST:AC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000007:
  file.replace:
    - name: /etc/security/limits.conf
    - pattern: '^\s*\*\s+hard\s+maxlogins\s+.*$'
    - repl: '*	hard	maxlogins	10'
    - append_if_not_found: True
    - backup: False
