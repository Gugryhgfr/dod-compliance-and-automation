# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFR-9X-000013
# Title:   The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to disable Protocol Independent Multicast (PIM) o
# Severity:medium  CCI:CCI-001414  NIST:AC-4
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

VCFR-9X-000013_api:
  cmd.run:
    - name: 'curl -ksS -X PATCH ''https://localhost/policy/api/v1<<item.path>>'' -H ''Content-Type: application/json'' -d ''<<lookup(''template'', ''./nsx_routing_t0_disable_multicast_on_interface.json.j2'')>>'''
