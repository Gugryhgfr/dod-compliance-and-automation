# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000004
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must use cryptography to protect the integrity of remote 
# Severity:medium  CCI:CCI-000197,CCI-001453,CCI-002314,CCI-002418,CCI-002420,CCI-002422  NIST:AC-17 (1),AC-17 (2),IA-5 (1) (c),SC-8,SC-8 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000004:
  file.append:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - text: 'ssl.engine = "enable"'

VCFM-9X-000004_step2:
  file.replace:
    - name: /etc/lighttpd/vhosts.d/applmgmt-lighttpd.conf
    - pattern: '^(ssl\.engine\s*)=.*$'
    - repl: '\1= "enable"'
    - append_if_not_found: True
    - backup: False
