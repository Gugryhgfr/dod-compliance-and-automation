# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000160
# Title:   The Photon operating system must implement address space layout randomization to protect its memory from unauthoriz
# Severity:medium  CCI:CCI-002824  NIST:SI-16
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000160:
  sysctl.present:
    - name: kernel.randomize_va_space
    - value: 2
    - config: /etc/sysctl.d/zz-stig-hardening.conf
