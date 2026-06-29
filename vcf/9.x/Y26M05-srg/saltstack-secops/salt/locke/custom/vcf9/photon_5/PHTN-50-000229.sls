# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000229
# Title:   The Photon operating system must use a reverse-path filter for IPv4 network traffic.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000229:
  sysctl.present:
    - name: net.ipv4.conf.all.rp_filter
    - value: 1
    - config: /etc/sysctl.d/zz-stig-hardening.conf

PHTN-50-000229_step2:
  sysctl.present:
    - name: net.ipv4.conf.default.rp_filter
    - value: 1
    - config: /etc/sysctl.d/zz-stig-hardening.conf
