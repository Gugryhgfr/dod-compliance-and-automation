# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000047
# Title:   The Photon operating system must disable unnecessary kernel modules.
# Severity:medium  CCI:CCI-000381,CCI-000778  NIST:CM-7 a,IA-3
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000047:
  file.managed:
    - name: /etc/modprobe.d/modprobe.conf
    - mode: 0644
    - user: root
    - group: root
    - source: 'salt://vcf9/files/PHTN-50-000047'
    - template: jinja
