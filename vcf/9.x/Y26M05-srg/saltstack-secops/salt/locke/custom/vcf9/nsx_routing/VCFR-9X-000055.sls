# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFR-9X-000055
# Title:   The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to use a unique password for each autonomous syst
# Severity:medium  CCI:CCI-001184  NIST:SC-23
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFR-9X-000055_manual:
  test.succeed_with_changes:
    - name: VCFR-9X-000055 requires manual review. See meta global_description / remediation.
