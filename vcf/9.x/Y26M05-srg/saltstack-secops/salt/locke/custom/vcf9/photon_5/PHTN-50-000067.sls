# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000067
# Title:   The Photon operating system must restrict access to the kernel message buffer.
# Severity:medium  CCI:CCI-001090  NIST:SC-4
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000067:
  sysctl.present:
    - name: kernel.dmesg_restrict
    - value: 1
    - config: /etc/sysctl.d/zz-stig-hardening.conf
