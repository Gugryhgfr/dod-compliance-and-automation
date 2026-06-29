# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFI-9X-000032
# Title:   The VMware Cloud Foundation Operations PostgreSQL service must not load unused database components, software, and d
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFI-9X-000032_manual:
  test.succeed_with_changes:
    - name: VCFI-9X-000032 requires manual review. See meta global_description / remediation.
