# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFR-9X-000111
# Title:   The VMware Cloud Foundation NSX Tier-0 Gateway router must be configured to use encryption for BGP routing protocol
# Severity:medium  CCI:CCI-000803  NIST:IA-7
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFR-9X-000111_manual:
  test.succeed_with_changes:
    - name: VCFR-9X-000111 requires manual review. See meta global_description / remediation.
