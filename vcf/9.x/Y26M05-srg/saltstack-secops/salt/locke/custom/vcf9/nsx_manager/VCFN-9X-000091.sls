# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000091
# Title:   The VMware Cloud Foundation NSX Manager must be configured to conduct backups on an organizationally defined schedu
# Severity:medium  CCI:CCI-000366,CCI-000537,CCI-000539  NIST:CM-6 b,CP-9 (b),CP-9 (c)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFN-9X-000091_manual:
  test.succeed_with_changes:
    - name: VCFN-9X-000091 requires manual review. See meta global_description / remediation.
