# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000009
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must produce log records containing sufficient informatio
# Severity:medium  CCI:CCI-000130,CCI-000131,CCI-000132,CCI-000133,CCI-000134,CCI-001487,CCI-001889,CCI-001890  NIST:AU-3 a,AU-3 b,AU-3 c,AU-3 d,AU-3 e,AU-3 f,AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000009:
  file.replace:
    - name: /etc/lighttpd/conf.d/access_log.conf
    - pattern: '^accesslog\.format.*$'
    - repl: ''
    - backup: False

VCFM-9X-000009_step2:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '^accesslog\.format.*$'
    - repl: ''
    - backup: False

VCFM-9X-000009_step3:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^accesslog\.format.*$'
    - repl: ''
    - backup: False
