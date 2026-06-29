# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000065
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must disable directory listing.
# Severity:medium  CCI:CCI-001312  NIST:SI-11 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000065:
  file.replace:
    - name: /etc/lighttpd/modules.conf
    - pattern: '^\s+"mod_dirlisting",?$'
    - repl: ''
    - backup: False

VCFM-9X-000065_step2:
  file.replace:
    - name: /etc/lighttpd/modules.conf
    - pattern: '(^server\.modules\s+)(=|\+=\s+)(.*)("mod_dirlisting",?\s?)(.*$)'
    - repl: \1\2\3\5
    - append_if_not_found: True
    - backup: False

VCFM-9X-000065_step3:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '^\s+"mod_dirlisting",?$'
    - repl: ''
    - backup: False

VCFM-9X-000065_step4:
  file.replace:
    - name: /etc/lighttpd/lighttpd.conf
    - pattern: '(^server\.modules\s+)(=|\+=\s+)(.*)("mod_dirlisting",?\s?)(.*$)'
    - repl: \1\2\3\5
    - append_if_not_found: True
    - backup: False

VCFM-9X-000065_step5:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^\s+"mod_dirlisting",?$'
    - repl: ''
    - backup: False

VCFM-9X-000065_step6:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '(^server\.modules\s+)(=|\+=\s+)(.*)("mod_dirlisting",?\s?)(.*$)'
    - repl: \1\2\3\5
    - append_if_not_found: True
    - backup: False
