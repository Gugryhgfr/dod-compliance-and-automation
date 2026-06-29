# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000003
# Title:   The VMware Cloud Foundation Operations Apache HTTP service must use cryptography to protect the integrity of remote
# Severity:medium  CCI:CCI-000068,CCI-000197,CCI-000213,CCI-001188,CCI-001453,CCI-002418,CCI-002420,CCI-002422,CCI-002470  NIST:AC-17 (2),AC-3,IA-5 (1) (c),SC-23 (3),SC-23 (5),SC-8,SC-8 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFH-9X-000003:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: LoadModule ssl_module /usr/lib64/httpd/modules/mod_ssl.so

VCFH-9X-000003_step2:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LoadModule\s*)(ssl_module\s?)(.*)$'
    - repl: \1\2/usr/lib64/httpd/modules/mod_ssl.so
    - append_if_not_found: True
    - backup: False

VCFH-9X-000003_step3:
  file.replace:
    - name: /etc/httpd/conf/extra/httpd-ssl.conf
    - pattern: '(?!^#)(^\s*SSLProtocol\s*)(.*)$'
    - repl: ''
    - backup: False

VCFH-9X-000003_step4:
  file.append:
    - name: /etc/httpd/conf/extra/httpd-ssl.conf
    - text: SSLProtocol -All +TLSv1.2 +TLSv1.3

VCFH-9X-000003_step5:
  file.replace:
    - name: /etc/httpd/conf/extra/httpd-ssl.conf
    - pattern: '(?!^#)(^\s*SSLProtocol\s*)(.*)$'
    - repl: \1-All +TLSv1.2 +TLSv1.3
    - append_if_not_found: True
    - backup: False
