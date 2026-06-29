# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000080
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service configuration files must only be accessible to privi
# Severity:medium  CCI:CCI-001813,CCI-002235  NIST:AC-6 (10),CM-5 (1) (a)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFJ-9X-000080:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: o-w
    - user: root
    - group: root
