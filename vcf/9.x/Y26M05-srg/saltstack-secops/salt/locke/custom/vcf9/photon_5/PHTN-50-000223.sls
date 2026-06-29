# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000223
# Title:   The Photon operating system must not forward IPv4 or IPv6 source-routed packets.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000223:
  sysctl.present:
    - name: net.ipv4.conf.all.accept_source_route
    - value: 0
    - config: /etc/sysctl.d/zz-stig-hardening.conf

PHTN-50-000223_step2:
  sysctl.present:
    - name: net.ipv4.conf.default.accept_source_route
    - value: 0
    - config: /etc/sysctl.d/zz-stig-hardening.conf

PHTN-50-000223_step3:
  sysctl.present:
    - name: net.ipv6.conf.all.accept_source_route
    - value: 0
    - config: /etc/sysctl.d/zz-stig-hardening.conf

PHTN-50-000223_step4:
  sysctl.present:
    - name: net.ipv6.conf.default.accept_source_route
    - value: 0
    - config: /etc/sysctl.d/zz-stig-hardening.conf
