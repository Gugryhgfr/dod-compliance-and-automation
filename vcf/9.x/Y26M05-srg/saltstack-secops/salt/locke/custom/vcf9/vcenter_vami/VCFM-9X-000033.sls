# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000033
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must have Web Distributed Authoring (WebDAV) disabled.
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000033:
  file.replace:
    - name: /etc/lighttpd/modules.conf
    - pattern: '^\s+"mod_webdav",?$'
    - repl: ''
    - backup: False

VCFM-9X-000033_step2:
  file.replace:
    - name: /etc/lighttpd/modules.conf
    - pattern: '(^server\.modules\s+)(=|\+=\s+)(.*)("mod_webdav",?\s?)(.*$)'
    - repl: \1\2\3\5
    - append_if_not_found: True
    - backup: False

VCFM-9X-000033_step3:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '^\s+"mod_webdav",?$'
    - repl: ''
    - backup: False

VCFM-9X-000033_step4:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '(^server\.modules\s+)(=|\+=\s+)(.*)("mod_webdav",?\s?)(.*$)'
    - repl: \1\2\3\5
    - append_if_not_found: True
    - backup: False

VCFM-9X-000033_step5:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^\s+"mod_webdav",?$'
    - repl: ''
    - backup: False

VCFM-9X-000033_step6:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '(^server\.modules\s+)(=|\+=\s+)(.*)("mod_webdav",?\s?)(.*$)'
    - repl: \1\2\3\5
    - append_if_not_found: True
    - backup: False
