# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFR-9X-000091
# Title:   The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to use its loopback address as the source address
# Severity:low  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFR-9X-000091_manual:
  test.succeed_with_changes:
    - name: VCFR-9X-000091 requires manual review. See meta global_description / remediation.
