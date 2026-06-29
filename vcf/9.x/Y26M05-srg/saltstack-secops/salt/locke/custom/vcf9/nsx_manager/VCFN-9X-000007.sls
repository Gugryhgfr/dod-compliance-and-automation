# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000007
# Title:   The VMware Cloud Foundation NSX Manager must configure logging levels for services to ensure audit records are gene
# Severity:medium  CCI:CCI-000169,CCI-000172,CCI-000366,CCI-001403,CCI-001404  NIST:AC-2 (4),AU-12 a,AU-12 c,CM-6 b
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

VCFN-9X-000007_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/api/v1/node/services/async_replicator'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_node_async_loglevel.json.j2'')>>'''

VCFN-9X-000007_api_2:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/api/v1/node/services/auth'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_node_auth_loglevel.json.j2'')>>'''

VCFN-9X-000007_step3:
  file.managed:
    - name: '<<role_path>>/templates/nsx_manager_update_node_http_loglevel.json'
    - mode: 0640
    - source: 'salt://vcf9/files/VCFN-9X-000007'
    - template: jinja

VCFN-9X-000007_cmd:
  cmd.run:
    - name: 'sed -i ''s/NEWLINESPLVAR/\\n/g'' "<<role_path>>/templates/update_node_http_loglevel.json"'

VCFN-9X-000007_api_5:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/api/v1/node/services/http'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_node_http_loglevel.json'')>>'''

VCFN-9X-000007_step6:
  file.absent:
    - name: '<<role_path>>/templates/nsx_manager_update_node_http_loglevel.json'

VCFN-9X-000007_api_7:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/api/v1/node/services/manager'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_node_manager_loglevel.json.j2'')>>'''

VCFN-9X-000007_api_8:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/api/v1/node/services/telemetry'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_node_telemetry_loglevel.json.j2'')>>'''
