# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000039
# Title:   The VMware Cloud Foundation Operations Apache HTTP service private keys must be protected from unauthorized access.
# Severity:medium  CCI:CCI-000186,CCI-004910  NIST:IA-5 (2) (a) (1),SC-28 (3)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFH-9X-000039:
  file.managed:
    - name: '<<keyfile.stat.lnk_target>>'
    - replace: False
    - create: True
    - mode: 0400
    - user: admin
    - group: admin

VCFH-9X-000039_step2:
  file.managed:
    - name: '<<keyfile.stat.path>>'
    - replace: False
    - create: True
    - mode: 0400
    - user: admin
    - group: admin
