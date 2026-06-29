# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000228
# Title:   The Photon operating system must log IPv4 packets with impossible addresses.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000228:
  sysctl.present:
    - name: net.ipv4.conf.all.log_martians
    - value: 1
    - config: /etc/sysctl.d/zz-stig-hardening.conf

PHTN-50-000228_step2:
  sysctl.present:
    - name: net.ipv4.conf.default.log_martians
    - value: 1
    - config: /etc/sysctl.d/zz-stig-hardening.conf
