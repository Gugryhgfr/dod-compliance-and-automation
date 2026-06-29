# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000051
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must write log entries to disk prior to returning opera
# Severity:medium  CCI:CCI-001665  NIST:SC-24
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000051_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET fsync = on;"'
    - unless: 'echo check | grep -q ''on''  # verify fsync=on manually'

VCFC-9X-000051_cmd_2:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET full_page_writes = on;"'
    - unless: 'echo check | grep -q ''on''  # verify full_page_writes=on manually'

VCFC-9X-000051_cmd_3:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET synchronous_commit = on;"'
    - unless: 'echo check | grep -q ''on''  # verify synchronous_commit=on manually'
