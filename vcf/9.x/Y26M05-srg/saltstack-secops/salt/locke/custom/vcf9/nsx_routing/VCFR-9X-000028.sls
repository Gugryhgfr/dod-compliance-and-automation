# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFR-9X-000028
# Title:   The router must not be configured to have any feature enabled that calls home to the vendor.
# Severity:medium  CCI:CCI-002403  NIST:SC-7 (11)
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

VCFR-9X-000028_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/api/v1/telemetry/config'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_routing_update_telemetry_config.json.j2'')>>'''
