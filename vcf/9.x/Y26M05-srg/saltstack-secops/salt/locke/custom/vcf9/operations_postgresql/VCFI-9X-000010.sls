# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000010
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must produce logs containing sufficient information to es
# Severity:medium  CCI:CCI-000130,CCI-000131,CCI-000132,CCI-000133,CCI-000134,CCI-000135,CCI-001487,CCI-001889  NIST:AU-3 (1),AU-3 a,AU-3 b,AU-3 c,AU-3 d,AU-3 e,AU-3 f,AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFI-9X-000010_cmd:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET log_line_prefix = ''%m %c %x %d %u %r %p %l'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW log_line_prefix\"" | grep -qi ''%m\ %c\ %x\ %d\ %u\ %r\ %p\ %l'''
