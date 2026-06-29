# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000032
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must have resource mappings set to disable the serving of
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000032:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '^url\.access-deny.*$'
    - repl: ''
    - backup: False

VCFM-9X-000032_step2:
  file.append:
    - name: /etc/lighttpd/lighttpd.conf
    - text: 'url.access-deny = ( "~", ".inc" )'

VCFM-9X-000032_step3:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '^(url\.access-deny\s*)=.*$'
    - repl: '\1= ( "~", ".inc" )'
    - append_if_not_found: True
    - backup: False
