# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000005
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must enable "pgaudit" to provide audit record generation cap
# Severity:medium  CCI:CCI-000169  NIST:AU-12 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains an unguarded cmd.run step (no on-host audit could be derived).
#          Under test=True this step always reports a pending change. Add an
#          'unless'/'onlyif' guard or an attestation to assess accurately.
# Tier: ansible-native-unguarded

VCFL-9X-000005:
  file.managed:
    - name: /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
    - replace: False
    - create: True
    - mode: 0744

VCFL-9X-000005_cmd:
  cmd.run:
    - name: /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py --action stig_enable --pg-data-dir /storage/db/vpostgres

VCFL-9X-000005_step3:
  file.managed:
    - name: /opt/vmware/vpostgres/current/bin/vmw_vpg_config/vmw_vpg_config.py
    - replace: False
    - create: True
    - mode: 0644
