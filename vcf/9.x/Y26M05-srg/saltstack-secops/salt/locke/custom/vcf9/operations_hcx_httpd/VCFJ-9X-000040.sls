# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000040
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must use FIPS validated cryptographic modules.
# Severity:high  CCI:CCI-000803,CCI-001188,CCI-002418,CCI-002450  NIST:IA-7,SC-13 b,SC-23 (3),SC-8
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000040:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: LoadModule ssl_module /usr/lib/httpd/modules/mod_ssl.so

VCFJ-9X-000040_step2:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LoadModule\s*)(ssl_module\s?)(.*)$'
    - repl: \1\2/usr/lib/httpd/modules/mod_ssl.so
    - append_if_not_found: True
    - backup: False

VCFJ-9X-000040_step3:
  file.replace:
    - name: /etc/httpd/conf/fips.conf
    - pattern: '(?!^#)(^\s*SSLFIPS\s*)(.*)$'
    - repl: ''
    - backup: False

VCFJ-9X-000040_step4:
  file.append:
    - name: /etc/httpd/conf/fips.conf
    - text: SSLFIPS ON

VCFJ-9X-000040_step5:
  file.replace:
    - name: /etc/httpd/conf/fips.conf
    - pattern: '(?!^#)(^\s*SSLFIPS\s*)(.*)$'
    - repl: \1ON
    - append_if_not_found: True
    - backup: False
