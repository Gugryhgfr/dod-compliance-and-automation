# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000101
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must disable client initiated TLS renegotiation.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000101:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '^ssl\.disable-client-renegotiation.*$'
    - repl: ''
    - backup: False

VCFM-9X-000101_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^ssl\.disable-client-renegotiation.*$'
    - repl: ''
    - backup: False
