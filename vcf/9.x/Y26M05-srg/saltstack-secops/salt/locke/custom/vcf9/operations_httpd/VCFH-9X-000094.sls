# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000094
# Title:   The VMware Cloud Foundation Operations Apache HTTP service must enable HTTP/2.
# Severity:medium  CCI:CCI-002418  NIST:SC-8
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFH-9X-000094_manual:
  test.succeed_with_changes:
    - name: VCFH-9X-000094 requires manual review. See meta global_description / remediation.
