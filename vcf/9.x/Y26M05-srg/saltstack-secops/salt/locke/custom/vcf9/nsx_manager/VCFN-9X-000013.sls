# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000013
# Title:   The VMware Cloud Foundation NSX Manager must display the Standard Mandatory DoD Notice and Consent Banner before gr
# Severity:medium  CCI:CCI-000048,CCI-000050  NIST:AC-8 a,AC-8 b
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

VCFN-9X-000013_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/policy/api/v1/loginbanner'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_loginbanner.json.j2'')>>'''
