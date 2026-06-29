# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFO-9X-000025
# Title:   The VMware Cloud Foundation Operations for Networks Platform NGINX server must not perform user management for host
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFO-9X-000025_manual:
  test.succeed_with_changes:
    - name: VCFO-9X-000025 requires manual review. See meta global_description / remediation.
