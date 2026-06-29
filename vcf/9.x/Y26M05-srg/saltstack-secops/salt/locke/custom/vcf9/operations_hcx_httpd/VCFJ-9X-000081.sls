# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000081
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must prohibit or restrict the use of nonsecure or un
# Severity:medium  CCI:CCI-001762  NIST:CM-7 (1) (b)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFJ-9X-000081_manual:
  test.succeed_with_changes:
    - name: VCFJ-9X-000081 requires manual review. See meta global_description / remediation.
