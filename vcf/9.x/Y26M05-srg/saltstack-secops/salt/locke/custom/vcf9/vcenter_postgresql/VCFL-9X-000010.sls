# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000010
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must produce logs containing sufficient information to estab
# Severity:medium  CCI:CCI-000130,CCI-000131,CCI-000132,CCI-000133,CCI-000134,CCI-000135,CCI-001487,CCI-001889  NIST:AU-3 (1),AU-3 a,AU-3 b,AU-3 c,AU-3 d,AU-3 e,AU-3 f,AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000010:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^log_line_prefix =
    - repl: 'log_line_prefix = ''%m %c %x %d %u %r %p %l'''
    - append_if_not_found: True
    - backup: False
