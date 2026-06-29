# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000113
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must log all client disconnections.
# Severity:medium  CCI:CCI-000172  NIST:AU-12 c
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000113:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^log_disconnections =
    - repl: log_disconnections = on
    - append_if_not_found: True
    - backup: False
