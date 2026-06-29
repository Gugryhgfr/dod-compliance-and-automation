# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000105
# Title:   The Photon operating system must enable symlink access control protection in the kernel.
# Severity:high  CCI:CCI-002235  NIST:AC-6 (10)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000105:
  sysctl.present:
    - name: fs.protected_symlinks
    - value: 1
    - config: /etc/sysctl.d/zz-stig-hardening.conf
