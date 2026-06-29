# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000026
# Title:   The Photon operating system must protect audit logs from unauthorized access.
# Severity:medium  CCI:CCI-000162,CCI-000163,CCI-000164  NIST:AU-9 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

PHTN-50-000026:
  file.managed:
    - name: '<<auditlog>>'
    - replace: False
    - create: True
    - mode: 0600
    - user: root
    - group: root

PHTN-50-000026_step2:
  file.replace:
    - name: /etc/audit/auditd.conf
    - pattern: '^\s*#?\s*log_group\s*=\s*.*$'
    - repl: log_group = root
    - append_if_not_found: True
    - backup: False
