# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000001
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must limit the number of allowed simultaneous sessio
# Severity:medium  CCI:CCI-000054  NIST:AC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000001:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*KeepAlive\s+)(.*)$'
    - repl: \1On
    - append_if_not_found: True
    - backup: False

VCFJ-9X-000001_step2:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*MaxKeepAliveRequests\s+)(.*)$'
    - repl: '\g<1>100'
    - append_if_not_found: True
    - backup: False
