# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000035
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must be configured to use an authorized port.
# Severity:medium  CCI:CCI-000382,CCI-001762  NIST:CM-7 (1) (b),CM-7 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFI-9X-000035_cmd:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET port = ''5433'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW port\"" | grep -qi ''5433'''
