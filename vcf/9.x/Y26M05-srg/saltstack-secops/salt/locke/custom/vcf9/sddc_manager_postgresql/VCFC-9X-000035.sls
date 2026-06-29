# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000035
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must be configured to use an authorized port.
# Severity:medium  CCI:CCI-000382,CCI-001762  NIST:CM-7 (1) (b),CM-7 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000035_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET port = 5432;"'
    - unless: 'echo check | grep -q ''5432''  # verify port=5432 manually'
