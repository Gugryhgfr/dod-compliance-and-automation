# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000067
# Title:   The VMware Cloud Foundation Operations Apache HTTP service must disable debugging and trace information.
# Severity:medium  CCI:CCI-001312  NIST:SI-11 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFH-9X-000067:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*TraceEnable\s*)(.*)$'
    - repl: ''
    - backup: False

VCFH-9X-000067_step2:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*TraceEnable\s*)(.*)$'
    - repl: \1Off
    - append_if_not_found: True
    - backup: False
