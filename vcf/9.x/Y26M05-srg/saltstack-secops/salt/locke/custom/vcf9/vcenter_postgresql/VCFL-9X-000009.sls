# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000009
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must initiate session auditing upon startup.
# Severity:medium  CCI:CCI-001464  NIST:AU-14 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000009:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^log_destination =
    - repl: log_destination = stderr
    - append_if_not_found: True
    - backup: False
