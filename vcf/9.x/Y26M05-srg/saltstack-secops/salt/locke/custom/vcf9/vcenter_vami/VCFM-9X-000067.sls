# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000067
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must have debug logging disabled.
# Severity:medium  CCI:CCI-001312  NIST:SI-11 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000067:
  file.append:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - text: 'debug.log-request-handling = "disable"'

VCFM-9X-000067_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^(debug\.log-request-handling\s*)=.*$'
    - repl: '\1= "disable"'
    - append_if_not_found: True
    - backup: False
