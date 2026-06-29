# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000001
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must limit the number of allowed simultaneous session req
# Severity:medium  CCI:CCI-000054  NIST:AC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000001:
  file.append:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - text: server.max-connections = 1024

VCFM-9X-000001_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^(server\.max-connections\s*)=.*$'
    - repl: \1= 1024
    - append_if_not_found: True
    - backup: False
