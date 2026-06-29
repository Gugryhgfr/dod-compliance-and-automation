# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFL-9X-000001
# Title:   The VMware Cloud Foundation vCenter PostgreSQL service must limit the number of concurrent sessions.
# Severity:medium  CCI:CCI-000054  NIST:AC-10
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFL-9X-000001_manual:
  test.succeed_with_changes:
    - name: VCFL-9X-000001 requires manual review. See meta global_description / remediation.
