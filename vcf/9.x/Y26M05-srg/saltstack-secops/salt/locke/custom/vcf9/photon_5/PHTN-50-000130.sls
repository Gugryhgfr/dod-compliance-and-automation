# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000130
# Title:   The Photon operating system TDNF package management tool must cryptographically verify the authenticity of all soft
# Severity:high  CCI:CCI-003992  NIST:CM-14
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000130:
  file.replace:
    - name: /etc/tdnf/tdnf.conf
    - pattern: '^\s*#?\s*gpgcheck\s*=\s*.*$'
    - repl: gpgcheck=1
    - append_if_not_found: True
    - backup: False
