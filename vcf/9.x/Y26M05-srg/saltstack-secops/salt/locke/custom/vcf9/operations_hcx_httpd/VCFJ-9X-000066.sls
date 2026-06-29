# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000066
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must minimize the identity of the web server.
# Severity:medium  CCI:CCI-001312  NIST:SI-11 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000066:
  file.replace:
    - name: /opt/vmware/config/apache-httpd/hcx-ssl.conf
    - pattern: '(?!^#)(^\s*ServerSignature\s*)(.*)$'
    - repl: ''
    - backup: False

VCFJ-9X-000066_step2:
  file.replace:
    - name: /opt/vmware/config/apache-httpd/hcx-ssl.conf
    - pattern: '(?!^#)(^\s*ServerSignature\s*)(.*)$'
    - repl: \1Off
    - append_if_not_found: True
    - backup: False

VCFJ-9X-000066_step3:
  file.replace:
    - name: /opt/vmware/config/apache-httpd/hcx-ssl.conf
    - pattern: '(?!^#)(^\s*ServerTokens\s*)(.*)$'
    - repl: ''
    - backup: False

VCFJ-9X-000066_step4:
  file.append:
    - name: /opt/vmware/config/apache-httpd/hcx-ssl.conf
    - text: ServerTokens Prod

VCFJ-9X-000066_step5:
  file.replace:
    - name: /opt/vmware/config/apache-httpd/hcx-ssl.conf
    - pattern: '(?!^#)(^\s*ServerTokens\s*)(.*)$'
    - repl: \1Prod
    - append_if_not_found: True
    - backup: False
