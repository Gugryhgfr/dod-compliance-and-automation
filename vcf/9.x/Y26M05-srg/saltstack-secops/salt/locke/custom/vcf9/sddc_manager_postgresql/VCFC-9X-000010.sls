# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000010
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must produce logs containing sufficient information to 
# Severity:medium  CCI:CCI-000130,CCI-000131,CCI-000132,CCI-000133,CCI-000134,CCI-000135,CCI-001487,CCI-001889  NIST:AU-3 (1),AU-3 a,AU-3 b,AU-3 c,AU-3 d,AU-3 e,AU-3 f,AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000010_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET log_line_prefix = %m %c %x %d %u %r %p %l;"'
    - unless: 'echo check | grep -q ''%m\ %c\ %x\ %d\ %u\ %r\ %p\ %l''  # verify log_line_prefix=%m %c %x %d %u %r %p %l manually'
