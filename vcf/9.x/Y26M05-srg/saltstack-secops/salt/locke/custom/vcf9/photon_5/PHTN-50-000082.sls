# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000082
# Title:   The Photon operating system must protect audit tools from unauthorized access.
# Severity:medium  CCI:CCI-001493,CCI-001494,CCI-001495  NIST:AU-9,AU-9 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

PHTN-50-000082:
  file.managed:
    - name: '<<item.stat.path>>'
    - replace: False
    - create: True
    - mode: 0755
    - user: root
    - group: root

PHTN-50-000082_step2:
  file.managed:
    - name: '<<item.stat.path>>'
    - replace: False
    - create: True
    - mode: 0750
    - user: root
    - group: root
