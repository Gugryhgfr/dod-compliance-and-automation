# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000030
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must explicitly disable Multipurpose Internet Mail Extens
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000030:
  file.append:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - text: 'mimetype.use-xattr = "disable"'

VCFM-9X-000030_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^(mimetype\.use-xattr\s*)=.*$'
    - repl: '\1= "disable"'
    - append_if_not_found: True
    - backup: False
