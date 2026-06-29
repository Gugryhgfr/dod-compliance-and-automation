# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000020
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must be configured to protect log files from unauthoriz
# Severity:medium  CCI:CCI-000162,CCI-000163,CCI-000164  NIST:AU-9 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFC-9X-000020_cmd:
  cmd.run:
    - name: '/usr/pgsql/15/bin/psql -h localhost -U postgres -c "ALTER SYSTEM SET log_file_mode = 0600;"'
    - unless: 'echo check | grep -q ''0600''  # verify log_file_mode=0600 manually'

VCFC-9X-000020_step2:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: 0600
    - user: postgres
    - group: users
