# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000009
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must produce log records containing sufficient infor
# Severity:medium  CCI:CCI-000130  NIST:AU-3 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000009:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*ErrorLog\s*)(.*)$'
    - repl: ''
    - backup: False

VCFJ-9X-000009_step2:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: 'ErrorLog "/common/logs/httpd/error.log"'

VCFJ-9X-000009_step3:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*ErrorLog\s*)(.*)$'
    - repl: '\1"/common/logs/httpd/error.log"'
    - append_if_not_found: True
    - backup: False

VCFJ-9X-000009_step4:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LogLevel\s*)(.*)$'
    - repl: ''
    - backup: False

VCFJ-9X-000009_step5:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: LogLevel info

VCFJ-9X-000009_step6:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LogLevel\s*)(.*)$'
    - repl: \1info
    - append_if_not_found: True
    - backup: False
