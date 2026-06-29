# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000068
# Title:   The Photon operating system must be configured to use TCP syncookies.
# Severity:medium  CCI:CCI-001095,CCI-002385  NIST:SC-5 (2),SC-5 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000068:
  sysctl.present:
    - name: net.ipv4.tcp_syncookies
    - value: 1
    - config: /etc/sysctl.d/zz-stig-hardening.conf
