# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000127
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must implement HTTP Strict Transport Security (HSTS).
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000127:
  file.append:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - text: 'setenv.add-response-header += ("Strict-Transport-Security" => "max-age=31536000; includeSubDomains; preload")'

VCFM-9X-000127_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '(^\s+"Strict-Transport-Security"\s+=>\s+)(".*")(.*$)'
    - repl: '\1"max-age=31536000; includeSubDomains; preload"\3'
    - append_if_not_found: True
    - backup: False

VCFM-9X-000127_step3:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '(^setenv\.add-response-header\s+)(=|\+=)(\s+\("Strict-Transport-Security"\s+=>\s+)(".*")(.*$)'
    - repl: '\1\2\3"max-age=31536000; includeSubDomains; preload"\5'
    - append_if_not_found: True
    - backup: False
