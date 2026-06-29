# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000016
# Title:   The Photon operating system must enable the auditd service.
# Severity:medium  CCI:CCI-000132,CCI-000133,CCI-000134,CCI-000135,CCI-000169,CCI-001487,CCI-003938  NIST:AU-12 a,AU-3 (1),AU-3 c,AU-3 d,AU-3 e,AU-3 f,CM-5 (1) (b)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000016:
  pkg.installed:
    - name: audit

PHTN-50-000016_step2:
  service.running:
    - name: auditd
    - enable: True
