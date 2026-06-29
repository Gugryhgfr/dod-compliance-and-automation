# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000386
# Title:   VMware Cloud Foundation Operations for Networks must be configured to forward logs to a central log server.
# Severity:medium  CCI:CCI-001851  NIST:AU-4 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFA-9X-000386_manual:
  test.succeed_with_changes:
    - name: VCFA-9X-000386 requires manual review. See meta global_description / remediation.
