# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000350
# Title:   VMware Cloud Foundation Operations must enable credential ownership enforcement.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains an unguarded cmd.run step (no on-host audit could be derived).
#          Under test=True this step always reports a pending change. Add an
#          'unless'/'onlyif' guard or an attestation to assess accurately.
# Tier: ansible-native-unguarded

VCFA-9X-000350_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/suite-api/api/deployment/config/globalsettings/ACTIVATE_CREDENTIAL_OWNERSHIP/true'''
