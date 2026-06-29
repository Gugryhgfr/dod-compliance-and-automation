# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000035
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must be configured to use an authorized port.
# Severity:medium  CCI:CCI-000382,CCI-001762  NIST:CM-7 (1) (b),CM-7 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000035:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^port =
    - repl: port = 5432
    - append_if_not_found: True
    - backup: False
