# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000017
# Title:   The VMware Cloud Foundation vCenter Server must enforce the limit of three consecutive invalid logon attempts by a 
# Severity:medium  CCI:CCI-000044  NIST:AC-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFA-9X-000017_manual:
  test.succeed_with_changes:
    - name: VCFA-9X-000017 requires manual review. See meta global_description / remediation.
