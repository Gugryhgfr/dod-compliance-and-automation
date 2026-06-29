# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000046
# Title:   The Photon operating system must require authentication upon booting into single-user and maintenance modes.
# Severity:medium  CCI:CCI-000213  NIST:AC-3
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: inspec-audit-only

PHTN-50-000046:
  cmd.run:
    - name: '/bin/false  # no automated remediation; see meta fix'
    - unless: 'grep -Pqz ''^set\ssuperusers=.*$'' ''/boot/grub2/grub.cfg'''
