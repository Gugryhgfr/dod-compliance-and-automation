# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000199
# Title:   The Photon operating system TDNF package management tool must cryptographically verify the authenticity of all soft
# Severity:high  CCI:CCI-003992  NIST:CM-14
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

PHTN-50-000199:
  file.replace:
    - name: '<<item.path>>'
    - pattern: '^\s*#?\s*gpgcheck\s*=\s*.*$'
    - repl: gpgcheck=1
    - append_if_not_found: True
    - backup: False
