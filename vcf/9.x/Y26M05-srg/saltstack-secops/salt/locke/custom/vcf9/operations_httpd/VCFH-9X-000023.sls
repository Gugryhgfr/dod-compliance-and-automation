# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000023
# Title:   The VMware Cloud Foundation Operations Apache HTTP service must not load modules that have not been fully reviewed,
# Severity:medium  CCI:CCI-000381,CCI-003992  NIST:CM-14,CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFH-9X-000023:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LoadModule\s*)(<<item>>\s?)(.*)$'
    - repl: '#\1\2\3'
    - append_if_not_found: True
    - backup: False
