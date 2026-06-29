# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000038
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must for password-based authentication, store passwords usin
# Severity:high  CCI:CCI-004062  NIST:IA-5 (1) (d)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFL-9X-000038:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^password_encryption =
    - repl: password_encryption = scram-sha-256
    - append_if_not_found: True
    - backup: False
