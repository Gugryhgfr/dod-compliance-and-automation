# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000063
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must interpret and normalize ambiguous HTTP requests.
# Severity:medium  CCI:CCI-001310  NIST:SI-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000063:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^server\.http-parseopts(\n|.)*?\)$'
    - repl: ''
    - backup: False

VCFM-9X-000063_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^server\.http-parseopts[^)]+\)$'
    - repl: ''
    - backup: False
