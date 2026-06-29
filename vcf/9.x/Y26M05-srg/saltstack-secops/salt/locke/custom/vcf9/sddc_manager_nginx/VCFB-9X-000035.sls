# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000035
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server worker process must be run as a nonprivileged user.
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFB-9X-000035_manual:
  test.succeed_with_changes:
    - name: VCFB-9X-000035 requires manual review. See meta global_description / remediation.
