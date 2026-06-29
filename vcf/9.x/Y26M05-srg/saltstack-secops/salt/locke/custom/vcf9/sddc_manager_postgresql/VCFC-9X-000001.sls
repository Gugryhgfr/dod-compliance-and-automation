# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000001
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must limit the number of concurrent sessions.
# Severity:medium  CCI:CCI-000054  NIST:AC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000001_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET max_connections = 100;"'
    - unless: 'echo check | grep -q ''100''  # verify max_connections=100 manually'
