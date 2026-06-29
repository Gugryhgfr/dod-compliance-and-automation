# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000006
# Title:   The VMware Cloud Foundation Operations PostgreSQL service configuration files must not be accessible by unauthorize
# Severity:medium  CCI:CCI-000171,CCI-001493,CCI-001494,CCI-001495,CCI-001813  NIST:AU-12 b,AU-9,AU-9 a,CM-5 (1) (a)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFI-9X-000006:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: 0600
    - user: postgres
    - group: users

VCFI-9X-000006_step2:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: 0600
    - user: postgres
    - group: users
