# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000051
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must write log entries to disk prior to returning operation 
# Severity:medium  CCI:CCI-001665  NIST:SC-24
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000051:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^fsync =
    - repl: fsync = on
    - append_if_not_found: True
    - backup: False

VCFL-9X-000051_step2:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^full_page_writes =
    - repl: full_page_writes = on
    - append_if_not_found: True
    - backup: False

VCFL-9X-000051_step3:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^synchronous_commit =
    - repl: synchronous_commit = on
    - append_if_not_found: True
    - backup: False
