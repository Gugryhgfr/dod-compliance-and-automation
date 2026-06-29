# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000051
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must write log entries to disk prior to returning operati
# Severity:medium  CCI:CCI-001665  NIST:SC-24
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFI-9X-000051_cmd:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET fsync = ''on'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW fsync\"" | grep -qi ''on'''

VCFI-9X-000051_cmd_2:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET full_page_writes = ''on'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW full_page_writes\"" | grep -qi ''on'''

VCFI-9X-000051_cmd_3:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET synchronous_commit = ''on'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW synchronous_commit\"" | grep -qi ''on'''
