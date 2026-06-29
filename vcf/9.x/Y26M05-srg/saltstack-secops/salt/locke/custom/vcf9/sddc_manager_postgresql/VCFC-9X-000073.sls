# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000073
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must use Coordinated Universal Time (UTC) for log times
# Severity:medium  CCI:CCI-001890  NIST:AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000073_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET log_timezone = UTC;"'
    - unless: 'echo check | grep -q ''UTC''  # verify log_timezone=UTC manually'
