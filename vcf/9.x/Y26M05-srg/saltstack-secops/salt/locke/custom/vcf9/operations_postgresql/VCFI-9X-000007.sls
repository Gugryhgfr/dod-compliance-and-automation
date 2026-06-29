# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000007
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must generate audit records.
# Severity:medium  CCI:CCI-000172,CCI-003938  NIST:AU-12 c,CM-5 (1) (b)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFI-9X-000007:
  file.replace:
    - name: /storage/db/vcops/vpostgres/repl/postgresql.conf
    - pattern: ^pgaudit.log =
    - repl: 'pgaudit.log = ''all, -misc, -read'''
    - append_if_not_found: True
    - backup: False

VCFI-9X-000007_step2:
  file.replace:
    - name: /storage/db/vcops/vpostgres/repl/postgresql.conf
    - pattern: ^pgaudit.log_catalog =
    - repl: pgaudit.log_catalog = off
    - append_if_not_found: True
    - backup: False

VCFI-9X-000007_step3:
  file.replace:
    - name: /storage/db/vcops/vpostgres/repl/postgresql.conf
    - pattern: ^pgaudit.log_parameter =
    - repl: pgaudit.log_parameter = off
    - append_if_not_found: True
    - backup: False

VCFI-9X-000007_step4:
  file.replace:
    - name: /storage/db/vcops/vpostgres/repl/postgresql.conf
    - pattern: ^pgaudit.log_statement =
    - repl: pgaudit.log_statement = off
    - append_if_not_found: True
    - backup: False

VCFI-9X-000007_step5:
  file.replace:
    - name: /storage/db/vcops/vpostgres/repl/postgresql.conf
    - pattern: ^pgaudit.log_relation =
    - repl: pgaudit.log_relation = off
    - append_if_not_found: True
    - backup: False
