# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000001
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must limit the number of concurrent sessions.
# Severity:medium  CCI:CCI-000054  NIST:AC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFI-9X-000001_cmd:
  cmd.run:
    - name: 'su - postgres -c ''/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c "ALTER SYSTEM SET max_connections = 200;"'''
    - unless: 'su - postgres -c ''/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW max_connections\"" | grep -qi ''200'''
