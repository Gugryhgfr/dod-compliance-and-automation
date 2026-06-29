# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000237
# Title:   The Photon operating system must configure AIDE to detect changes to baseline configurations.
# Severity:medium  CCI:CCI-001744  NIST:CM-3 (5)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains an unguarded cmd.run step (no on-host audit could be derived).
#          Under test=True this step always reports a pending change. Add an
#          'unless'/'onlyif' guard or an attestation to assess accurately.
# Tier: ansible-native-unguarded

PHTN-50-000237:
  file.managed:
    - name: /etc/aide.conf
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/PHTN-50-000237'
    - template: jinja

PHTN-50-000237_cmd:
  cmd.run:
    - name: aide --init

PHTN-50-000237_step3:
  file.managed:
    - name: /var/lib/aide/aide.db.gz
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/PHTN-50-000237'
