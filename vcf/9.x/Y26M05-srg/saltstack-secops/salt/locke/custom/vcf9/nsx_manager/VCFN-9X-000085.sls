# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000085
# Title:   The VMware Cloud Foundation NSX Manager must be configured to send logs to a central log server.
# Severity:medium  CCI:CCI-001849,CCI-001851  NIST:AU-4,AU-4 (1)
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

VCFN-9X-000085_api:
  cmd.run:
    - name: 'curl -ksS -X DELETE ''https://localhost/api/v1/node/services/syslog/exporters/<<item.exporter_name>>'''

VCFN-9X-000085_api_2:
  cmd.run:
    - name: 'curl -ksS -X POST ''https://localhost/api/v1/node/services/syslog/exporters'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_node_syslog_servers.json.j2'')>>'''
