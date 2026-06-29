# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000222
# Title:   The Photon operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the comm
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000222:
  service.running:
    - name: ctrl-alt-del.target
    - enable: False

PHTN-50-000222_step2:
  service.running:
    - name: ctrl-alt-del.target
