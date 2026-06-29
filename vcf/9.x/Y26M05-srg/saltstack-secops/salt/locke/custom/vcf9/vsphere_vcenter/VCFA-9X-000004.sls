# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000004
# Title:   The VMware Cloud Foundation vCenter Server must protect the confidentiality of network sessions.
# Severity:medium  CCI:CCI-000068,CCI-000382,CCI-001184,CCI-001453,CCI-001941,CCI-002420,CCI-002421,CCI-002422  NIST:AC-17 (2),CM-7 b,IA-2 (8),SC-23,SC-8 (1),SC-8 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFA-9X-000004_manual:
  test.succeed_with_changes:
    - name: VCFA-9X-000004 requires manual review. See meta global_description / remediation.
