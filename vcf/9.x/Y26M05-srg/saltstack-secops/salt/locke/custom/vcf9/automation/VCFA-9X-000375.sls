# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000375
# Title:   VMware Cloud Foundation Automation must disable unused feature flags.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
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

VCFA-9X-000375_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/cloudapi/1.0.0/featureFlags/<<item.id>>'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./automation_disable_feature_flag.json.j2'')>>'''
