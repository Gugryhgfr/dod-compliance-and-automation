# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000073
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must use Coordinated Universal Time (UTC) for log timesta
# Severity:medium  CCI:CCI-001890  NIST:AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFI-9X-000073_cmd:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET log_timezone = ''UTC'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW log_timezone\"" | grep -qi ''UTC'''
