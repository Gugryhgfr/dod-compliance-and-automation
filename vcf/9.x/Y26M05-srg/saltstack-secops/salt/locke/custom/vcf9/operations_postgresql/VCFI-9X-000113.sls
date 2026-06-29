# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000113
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must log all client disconnections.
# Severity:medium  CCI:CCI-000172  NIST:AU-12 c
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFI-9X-000113_cmd:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET log_disconnections = ''on'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW log_disconnections\"" | grep -qi ''on'''
