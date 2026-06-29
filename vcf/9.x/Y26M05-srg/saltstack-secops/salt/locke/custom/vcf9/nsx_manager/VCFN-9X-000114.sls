# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000114
# Title:   The VMware Cloud Foundation NSX Manager must enable the global FIPS compliance mode for load balancers.
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

VCFN-9X-000114_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/policy/api/v1/infra/global-config'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_manager_update_fips_for_lbs.json.j2'')>>'''
