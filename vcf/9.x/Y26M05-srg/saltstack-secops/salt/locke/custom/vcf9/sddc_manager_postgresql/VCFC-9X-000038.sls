# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000038
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must for password-based authentication, store passwords
# Severity:high  CCI:CCI-004062  NIST:IA-5 (1) (d)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000038_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET password_encryption = scram-sha-256;"'
    - unless: 'echo check | grep -q ''scram\-sha\-256''  # verify password_encryption=scram-sha-256 manually'
