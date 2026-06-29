# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000379
# Title:   VMware Cloud Foundation Operations for Networks must display the Standard Mandatory DOD Notice and Consent Banner b
# Severity:medium  CCI:CCI-000048  NIST:AC-8 a
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

VCFA-9X-000379_api:
  cmd.run:
    - name: 'curl -ksS -X POST ''https://localhost/api/ni/settings/loginBanner'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./ops_net_update_banner_settings.json.j2'')>>'''
