# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000085
# Title:   The Photon operating system must limit privileges to change software resident within software libraries.
# Severity:medium  CCI:CCI-001499  NIST:CM-5 (6)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

PHTN-50-000085:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: o-w
