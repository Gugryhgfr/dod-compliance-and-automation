# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000109
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must log all connection attempts.
# Severity:medium  CCI:CCI-000172  NIST:AU-12 c
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000109:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^log_connections =
    - repl: log_connections = on
    - append_if_not_found: True
    - backup: False
