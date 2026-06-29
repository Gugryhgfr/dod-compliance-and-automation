# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000331
# Title:   The VMware Cloud Foundation vCenter Server must have Mutual Challenge Handshake Authentication Protocol (CHAP) enab
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFA-9X-000331_manual:
  test.succeed_with_changes:
    - name: VCFA-9X-000331 requires manual review. See meta global_description / remediation.
