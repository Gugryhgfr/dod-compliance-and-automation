# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000130
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must enable Content Security Policy.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000130:
  file.append:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - text: 'setenv.add-response-header += ("Content-Security-Policy" => "default-src ''self''; img-src ''self'' data: https://scapi.telemetry.broadcom.com; connect-src ''self'' https://scapi.telemetry.broadcom.com; font-src ''self'' data:; object-src ''none''; style-src ''self'' ''unsafe-inline''")'

VCFM-9X-000130_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '(^\s+"Content-Security-Policy"\s+=>\s+)(".*")(.*$)'
    - repl: '\1"default-src ''self''; img-src ''self'' data: https://scapi.telemetry.broadcom.com; connect-src ''self'' https://scapi.telemetry.broadcom.com; font-src ''self'' data:; object-src ''none''; style-src ''self'' ''unsafe-inline''"\3'
    - append_if_not_found: True
    - backup: False

VCFM-9X-000130_step3:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '(^setenv\.add-response-header\s+)(=|\+=)(\s+\("Content-Security-Policy"\s+=>\s+)(".*")(.*$)'
    - repl: '\1\2\3"default-src ''self''; img-src ''self'' data: https://scapi.telemetry.broadcom.com; connect-src ''self'' https://scapi.telemetry.broadcom.com; font-src ''self'' data:; object-src ''none''; style-src ''self'' ''unsafe-inline''"\5'
    - append_if_not_found: True
    - backup: False
