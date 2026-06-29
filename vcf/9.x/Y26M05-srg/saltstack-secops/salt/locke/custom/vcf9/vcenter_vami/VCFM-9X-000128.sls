# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000128
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must implement prevent rendering inside a frame or iframe
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000128:
  file.append:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - text: 'setenv.add-response-header += ("X-Frame-Options" => "Deny")'

VCFM-9X-000128_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '(^\s+"X-Frame-Options"\s+=>\s+)(".*")(.*$)'
    - repl: '\1"Deny"\3'
    - append_if_not_found: True
    - backup: False

VCFM-9X-000128_step3:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '(^setenv\.add-response-header\s+)(=|\+=)(\s+\("X-Frame-Options"\s+=>\s+)(".*")(.*$)'
    - repl: '\1\2\3"Deny"\5'
    - append_if_not_found: True
    - backup: False
