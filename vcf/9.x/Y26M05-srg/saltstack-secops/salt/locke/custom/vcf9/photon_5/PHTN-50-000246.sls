# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000246
# Title:   The Photon operating system must restrict core dumps.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000246:
  sysctl.present:
    - name: fs.suid_dumpable
    - value: 0
    - config: /etc/sysctl.d/zz-stig-hardening.conf
