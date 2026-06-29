# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFB-9X-000034
# Title:   The VMware Cloud Foundation SDDC Manager NGINX server must have Web Distributed Authoring (WebDAV) disabled.
# Severity:medium  CCI:CCI-000381  NIST:CM-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual

VCFB-9X-000034_manual:
  test.succeed_with_changes:
    - name: VCFB-9X-000034 requires manual review. See meta global_description / remediation.
