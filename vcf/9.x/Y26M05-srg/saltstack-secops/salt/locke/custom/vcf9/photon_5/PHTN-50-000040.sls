# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000040
# Title:   The Photon operating system must not have the telnet package installed.
# Severity:high  CCI:CCI-000197  NIST:IA-5 (1) (c)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000040:
  pkg.removed:
    - pkgs: '[netkit-telnet, netkit-telnet-server]'
