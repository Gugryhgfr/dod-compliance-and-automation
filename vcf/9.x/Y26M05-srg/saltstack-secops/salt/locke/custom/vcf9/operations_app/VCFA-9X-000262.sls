# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000262
# Title:   VMware Cloud Foundation Operations must activate certificate validation.
# Severity:medium  CCI:CCI-000185  NIST:IA-5 (2) (b) (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
#
# WARNING: contains an unguarded cmd.run step (no on-host audit could be derived).
#          Under test=True this step always reports a pending change. Add an
#          'unless'/'onlyif' guard or an attestation to assess accurately.
# Tier: ansible-native-unguarded

VCFA-9X-000262_api:
  cmd.run:
    - name: 'curl -ksS -X PUT ''https://localhost/suite-api/api/deployment/config/globalsettings/ENABLE_CERTIFICATE_VALIDATION_STANDARD_WAY/true'''
