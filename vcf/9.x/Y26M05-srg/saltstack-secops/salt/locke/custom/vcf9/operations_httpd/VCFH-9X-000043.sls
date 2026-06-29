# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000043
# Title:   The VMware Cloud Foundation Operations Apache HTTP service directory tree must only be accessible by authorized acc
# Severity:medium  CCI:CCI-001082  NIST:SC-2
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFH-9X-000043:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: o-w
    - user: root
    - group: root
