# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000020
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must be configured to protect log files from unauthorized ac
# Severity:medium  CCI:CCI-000162,CCI-000163,CCI-000164  NIST:AU-9 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native

VCFL-9X-000020:
  file.replace:
    - name: /storage/db/vpostgres/stig.conf
    - pattern: ^log_file_mode =
    - repl: log_file_mode = 0600
    - append_if_not_found: True
    - backup: False

VCFL-9X-000020_step2:
  file.managed:
    - name: '<<item>>'
    - replace: False
    - create: True
    - mode: 0600
    - user: vpostgres
    - group: vpgmongrp
