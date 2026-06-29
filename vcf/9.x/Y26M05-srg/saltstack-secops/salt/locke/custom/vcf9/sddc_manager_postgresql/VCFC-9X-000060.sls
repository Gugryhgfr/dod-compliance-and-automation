# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000060
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must provide nonprivileged users with minimal error inf
# Severity:medium  CCI:CCI-001312,CCI-001314  NIST:SI-11 a,SI-11 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000060_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET client_min_messages = error;"'
    - unless: 'echo check | grep -q ''error''  # verify client_min_messages=error manually'
