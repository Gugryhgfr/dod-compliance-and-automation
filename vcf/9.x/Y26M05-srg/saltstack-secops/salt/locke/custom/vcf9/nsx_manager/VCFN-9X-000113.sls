# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000113
# Title:   The VMware Cloud Foundation NSX Manager must disable SNMP v2.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFN-9X-000113_manual:
  test.succeed_with_changes:
    - name: VCFN-9X-000113 requires manual review. See meta global_description / remediation.
