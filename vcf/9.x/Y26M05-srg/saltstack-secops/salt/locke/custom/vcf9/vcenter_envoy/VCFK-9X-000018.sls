# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFK-9X-000018
# Title:   The VMware Cloud Foundation vCenter Envoy services must protect log files from unauthorized access, modification, a
# Severity:medium  CCI:CCI-000162,CCI-000163,CCI-000164  NIST:AU-9 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFK-9X-000018:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: o-w
    - user: envoy
    - group: envoy

VCFK-9X-000018_step2:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: o-w
    - user: envoy-hgw
    - group: envoy-hgw

VCFK-9X-000018_step3:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: o-w
    - user: envoy-sidecar
    - group: envoy-sidecar

VCFK-9X-000018_step4:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: o-w
    - user: envoy-system-proxy
    - group: envoy-system-proxy
