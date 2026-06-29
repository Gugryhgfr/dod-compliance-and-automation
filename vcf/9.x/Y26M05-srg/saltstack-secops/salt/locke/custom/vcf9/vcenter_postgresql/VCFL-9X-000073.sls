# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000073
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must use Coordinated Universal Time (UTC) for log timestamps
# Severity:medium  CCI:CCI-001890  NIST:AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000073:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^log_timezone =
    - repl: log_timezone = UTC
    - append_if_not_found: True
    - backup: False
