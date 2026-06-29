# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000109
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must log all connection attempts.
# Severity:medium  CCI:CCI-000172  NIST:AU-12 c
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000109_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET log_connections = on;"'
    - unless: 'echo check | grep -q ''on''  # verify log_connections=on manually'
