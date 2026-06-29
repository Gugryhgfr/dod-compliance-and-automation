# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFN-9X-000010
# Title:   The VMware Cloud Foundation NSX Manager must be configured to assign appropriate user roles or access levels to aut
# Severity:high  CCI:CCI-000163,CCI-000164,CCI-000213,CCI-000345,CCI-000366,CCI-001199,CCI-001368,CCI-001493,CCI-001494,CCI-001495,CCI-001499,CCI-001813,CCI-002169,CCI-002235,CCI-002883,CCI-003831,CCI-003980  NIST:AC-3,AC-3 (7),AC-4,AC-6 (10),AU-9,AU-9 a,AU-9 b,CM-11 (2),CM-5,CM-5 (1) (a),CM-5 (6),CM-6 b,MA-3 (4),SC-28
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFN-9X-000010_manual:
  test.succeed_with_changes:
    - name: VCFN-9X-000010 requires manual review. See meta global_description / remediation.
