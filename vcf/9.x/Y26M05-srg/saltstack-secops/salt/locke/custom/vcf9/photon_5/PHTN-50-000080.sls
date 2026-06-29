# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000080
# Title:   The Photon operating system must initiate session audits at system start-up.
# Severity:medium  CCI:CCI-001464  NIST:AU-14 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000080:
  file.replace:
    - name: /boot/grub2/grub.cfg
    - pattern: '^(\s*linux(?!.* audit=).*)'
    - repl: \1 audit=1
    - backup: False

PHTN-50-000080_step2:
  file.replace:
    - name: /boot/grub2/grub.cfg
    - pattern: '^(\s*linux.*? audit=)(?!1)(\S*)(.*)'
    - repl: '\g<1>1\3'
    - backup: False

PHTN-50-000080_step3:
  file.replace:
    - name: /boot/grub2/grub.cfg
    - pattern: '^(\s*linux(?!.* fips=).*)'
    - repl: \1 fips=1
    - backup: False

PHTN-50-000080_step4:
  file.replace:
    - name: /boot/grub2/grub.cfg
    - pattern: '^(\s*linux.*? fips=)(?!1)(\S*)(.*)'
    - repl: '\g<1>1\3'
    - backup: False
