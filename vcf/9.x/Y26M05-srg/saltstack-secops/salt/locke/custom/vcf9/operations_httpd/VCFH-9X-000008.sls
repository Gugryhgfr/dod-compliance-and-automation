# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000008
# Title:   The VMware Cloud Foundation Operations Apache HTTP service must initiate session logging upon start up.
# Severity:medium  CCI:CCI-001464,CCI-001851  NIST:AU-14 (1),AU-4 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFH-9X-000008:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: LoadModule log_config_module /usr/lib/httpd/modules/mod_log_config.so

VCFH-9X-000008_step2:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LoadModule\s*)(log_config_module\s?)(.*)$'
    - repl: \1\2/usr/lib/httpd/modules/mod_log_config.so
    - append_if_not_found: True
    - backup: False

VCFH-9X-000008_step3:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*CustomLog\s*)(.*)$'
    - repl: ''
    - backup: False

VCFH-9X-000008_step4:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: 'CustomLog "/var/log/httpd/access.log" common'

VCFH-9X-000008_step5:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*CustomLog\s*)(.*)(common)$'
    - repl: '\1"/var/log/httpd/access.log" common'
    - append_if_not_found: True
    - backup: False
