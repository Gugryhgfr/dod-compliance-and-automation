# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000013
# Title:   The Photon operating system must have the OpenSSL FIPS provider installed to protect the confidentiality of remote 
# Severity:high  CCI:CCI-000068,CCI-002418,CCI-002420,CCI-002422,CCI-002890,CCI-003123  NIST:AC-17 (2),MA-4 (6),SC-8,SC-8 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000013:
  pkg.installed:
    - name: openssl-fips-provider
