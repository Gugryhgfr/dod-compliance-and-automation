# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000226
# Title:   The Photon operating system must prevent IPv4 Internet Control Message Protocol (ICMP) secure redirect messages fro
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000226:
  sysctl.present:
    - name: net.ipv4.conf.all.secure_redirects
    - value: 0
    - config: /etc/sysctl.d/zz-stig-hardening.conf

PHTN-50-000226_step2:
  sysctl.present:
    - name: net.ipv4.conf.default.secure_redirects
    - value: 0
    - config: /etc/sysctl.d/zz-stig-hardening.conf
