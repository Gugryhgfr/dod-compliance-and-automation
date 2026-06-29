# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000060
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must provide nonprivileged users with minimal error informat
# Severity:medium  CCI:CCI-001312,CCI-001314  NIST:SI-11 a,SI-11 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000060:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^client_min_messages =
    - repl: client_min_messages = error
    - append_if_not_found: True
    - backup: False
