# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000032
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must not load unused database components, software, and
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFC-9X-000032_manual:
  test.succeed_with_changes:
    - name: VCFC-9X-000032 requires manual review. See meta global_description / remediation.
