# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000034
# Title:   The VMware Cloud Foundation NSX Manager must be configured with only one local account to be used as the account of
# Severity:medium  CCI:CCI-001358,CCI-002111  NIST:AC-2 (7) (a),AC-2 a
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

VCFN-9X-000034_api:
  cmd.run:
    - name: 'curl -ksS -X POST ''https://localhost/api/v1/node/users/<<item.userid>>?action=deactivate'''
