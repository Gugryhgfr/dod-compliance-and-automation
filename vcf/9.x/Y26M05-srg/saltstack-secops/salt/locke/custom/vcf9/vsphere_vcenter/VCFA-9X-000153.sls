# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000153
# Title:   The VMware Cloud Foundation vCenter Server must compare internal information system clocks with an authoritative ti
# Severity:medium  CCI:CCI-004922,CCI-004923,CCI-004926  NIST:SC-45,SC-45 (1) (a),SC-45 (1) (b)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFA-9X-000153_manual:
  test.succeed_with_changes:
    - name: VCFA-9X-000153 requires manual review. See meta global_description / remediation.
