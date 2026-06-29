# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000125
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must protect system resources from hosted applications.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000125:
  file.append:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - text: server.max-keep-alive-idle = 30

VCFM-9X-000125_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^(server\.max-keep-alive-idle\s*)=.*$'
    - repl: \1= 30
    - append_if_not_found: True
    - backup: False
