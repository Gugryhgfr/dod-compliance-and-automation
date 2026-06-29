# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000234
# Title:   The Photon operating system must be configured to protect the Secure Shell (SSH) private host key from unauthorized
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

PHTN-50-000234:
  file.managed:
    - name: '<<item.path>>'
    - replace: False
    - create: True
    - mode: 0600
    - user: root
    - group: root
