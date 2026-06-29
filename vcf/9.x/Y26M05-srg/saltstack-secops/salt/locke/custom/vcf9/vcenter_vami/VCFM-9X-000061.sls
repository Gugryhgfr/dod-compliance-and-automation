# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000061
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must restrict the ability of users to launch denial-of-se
# Severity:medium  CCI:CCI-001094  NIST:SC-5 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000061:
  file.append:
    - name: /etc/lighttpd/lighttpd.conf
    - text: server.max-fds = 2048

VCFM-9X-000061_step2:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '^(server\.max-fds\s*)=.*$'
    - repl: \1= 2048
    - append_if_not_found: True
    - backup: False
