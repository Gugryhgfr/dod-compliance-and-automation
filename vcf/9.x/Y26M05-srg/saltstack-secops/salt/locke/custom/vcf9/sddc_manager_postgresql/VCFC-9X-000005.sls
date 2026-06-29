# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000005
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must enable "pgaudit" to provide audit record generatio
# Severity:medium  CCI:CCI-000169  NIST:AU-12 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000005:
  file.replace:
    - name: /data/pgdata/postgresql.conf
    - pattern: '^(shared_preload_libraries\s?=\s?)''((?!.*pgaudit).*)''$'
    - repl: '\g<1>''\g<2>,pgaudit'''
    - backup: False

VCFC-9X-000005_step2:
  file.replace:
    - name: /data/pgdata/postgresql.conf
    - pattern: ^shared_preload_libraries =
    - repl: 'shared_preload_libraries = ''pgaudit'''
    - append_if_not_found: True
    - backup: False
