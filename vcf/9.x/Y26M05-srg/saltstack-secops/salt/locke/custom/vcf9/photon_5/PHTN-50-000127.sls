# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000127
# Title:   The Photon operating system must install AIDE to detect changes to baseline configurations.
# Severity:medium  CCI:CCI-001744,CCI-002699  NIST:CM-3 (5),SI-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000127:
  pkg.installed:
    - pkgs: '[aide, libgcrypt]'
