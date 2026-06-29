# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000182
# Title:   The Photon operating system must implement NIST FIPS-validated cryptography for the following: to provision digital
# Severity:high  CCI:CCI-002450  NIST:SC-13 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000182:
  file.replace:
    - name: /boot/grub2/grub.cfg
    - pattern: '^(\s*linux(?!.* fips=).*)'
    - repl: \1 fips=1
    - backup: False

PHTN-50-000182_step2:
  file.replace:
    - name: /boot/grub2/grub.cfg
    - pattern: '^(\s*linux.*? fips=)(?!1)(\S*)(.*)'
    - repl: '\g<1>1\3'
    - backup: False
