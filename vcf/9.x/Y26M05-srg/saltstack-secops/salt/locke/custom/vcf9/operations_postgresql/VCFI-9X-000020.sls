# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000020
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must be configured to protect log files from unauthorized
# Severity:medium  CCI:CCI-000162,CCI-000163,CCI-000164  NIST:AU-9 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFI-9X-000020_cmd:
  cmd.run:
    - name: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"ALTER SYSTEM SET log_file_mode = ''0600'';\""'
    - unless: 'su - postgres -c "/opt/vmware/vpostgres/current/bin/psql -p 5433 -A -t -c \"SHOW log_file_mode\"" | grep -qi ''0600'''

VCFI-9X-000020_step2:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: 0600
    - user: postgres
    - group: users
