# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000033
# Title:   The VMware Cloud Foundation Operations Apache HTTP service must have Web Distributed Authoring (WebDAV) disabled.
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFH-9X-000033:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LoadModule\s*)(dav_module\s?)(.*)$'
    - repl: '#\1\2\3'
    - append_if_not_found: True
    - backup: False
