# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000024
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must not perform user management for hosted applicat
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFJ-9X-000024:
  file.replace:
    - name: '<<item>>'
    - pattern: '(?!^#)(^\s*AuthUserFile\s*)(.*)$'
    - repl: '#\1\2'
    - append_if_not_found: True
    - backup: False
