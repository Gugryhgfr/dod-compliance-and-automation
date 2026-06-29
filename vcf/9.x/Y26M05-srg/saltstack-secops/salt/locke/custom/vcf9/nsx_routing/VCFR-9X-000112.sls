# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFR-9X-000112
# Title:   The VMware Cloud Foundation NSX Tier-1 Gateway must be configured to have all inactive interfaces removed.
# Severity:low  CCI:CCI-001414  NIST:AC-4
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFR-9X-000112_manual:
  test.succeed_with_changes:
    - name: VCFR-9X-000112 requires manual review. See meta global_description / remediation.
