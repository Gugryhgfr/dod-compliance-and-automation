# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000062
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must set the encoding for all text mime types to UTF-8.
# Severity:medium  CCI:CCI-001310  NIST:SI-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFM-9X-000062:
  file.replace:
    - name: /etc/lighttpd/conf.d/mime.conf
    - pattern: '<<item>>'
    - repl: '<<item>>; charset=utf-8",'
    - append_if_not_found: True
    - backup: False
