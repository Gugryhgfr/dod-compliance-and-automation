# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000063
# Title:   The VMware Cloud Foundation vCenter Server must enforce password complexity requirements.
# Severity:medium  CCI:CCI-004066  NIST:IA-5 (1) (h)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFA-9X-000063_manual:
  test.succeed_with_changes:
    - name: VCFA-9X-000063 requires manual review. See meta global_description / remediation.
