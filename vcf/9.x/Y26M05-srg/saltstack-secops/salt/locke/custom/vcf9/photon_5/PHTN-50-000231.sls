# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000231
# Title:   The Photon operating system must not perform IPv4 packet forwarding.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000231:
  sysctl.present:
    - name: net.ipv4.ip_forward
    - value: 0
    - config: /etc/sysctl.d/zz-stig-hardening.conf
