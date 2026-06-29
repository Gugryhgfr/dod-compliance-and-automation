# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000061
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must restrict the ability of users to launch Denial 
# Severity:medium  CCI:CCI-001094,CCI-002385  NIST:SC-5 (1),SC-5 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000061:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*TimeOut\s*)(.*)$'
    - repl: ''
    - backup: False

VCFJ-9X-000061_step2:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*TimeOut\s*)(.*)$'
    - repl: \160
    - append_if_not_found: True
    - backup: False
