# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000111
# Title:   The VMware Cloud Foundation NSX Manager must be configured to synchronize system clocks with an authoritative time 
# Severity:medium  CCI:CCI-004922,CCI-004923  NIST:SC-45,SC-45 (1) (a)
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

VCFN-9X-000111_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/api/v1/node/services/ntp'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_node_ntp_servers.json.j2'')>>'''

VCFN-9X-000111_api_2:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/api/v1/node/services/ntp'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_node_ntp_servers.json.j2'')>>'''
