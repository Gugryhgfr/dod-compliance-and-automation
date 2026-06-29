# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000383
# Title:   VMware Cloud Foundation Operations HCX must compare internal information system clocks with an authoritative time s
# Severity:medium  CCI:CCI-004923  NIST:SC-45 (1) (a)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains an unguarded cmd.run step (no on-host audit could be derived).
#          Under test=True this step always reports a pending change. Add an
#          'unless'/'onlyif' guard or an attestation to assess accurately.
#
# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja
#          request-body templates that cannot be resolved statically. Supply these
#          values (pillar/template) before use - typically NSX/appliance REST bodies.
# Tier: ansible-native-unguarded

VCFA-9X-000383_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost:9443/system/timesettings'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./ops_hcx_update_time_servers.json.j2'')>>'''
