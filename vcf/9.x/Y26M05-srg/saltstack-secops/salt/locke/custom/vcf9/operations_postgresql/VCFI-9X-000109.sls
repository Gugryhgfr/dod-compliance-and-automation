# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000109
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must log all connection attempts.
# Severity:medium  CCI:CCI-000172  NIST:AU-12 c
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFI-9X-000109_cmd:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET log_connections = ''on'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW log_connections\"" | grep -qi ''on'''
