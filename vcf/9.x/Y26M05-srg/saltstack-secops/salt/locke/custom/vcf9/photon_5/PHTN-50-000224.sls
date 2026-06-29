# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000224
# Title:   The Photon operating system must not respond to IPv4 Internet Control Message Protocol (ICMP) echoes sent to a broa
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000224:
  sysctl.present:
    - name: net.ipv4.icmp_echo_ignore_broadcasts
    - value: 1
    - config: /etc/sysctl.d/zz-stig-hardening.conf
