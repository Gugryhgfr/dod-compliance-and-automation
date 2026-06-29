# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000034
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must protect system resources and privileged operati
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000034:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*User\s*)(admin)$'
    - repl: ''
    - backup: False

VCFJ-9X-000034_step2:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*Group\s*)(secureall)$'
    - repl: ''
    - backup: False
