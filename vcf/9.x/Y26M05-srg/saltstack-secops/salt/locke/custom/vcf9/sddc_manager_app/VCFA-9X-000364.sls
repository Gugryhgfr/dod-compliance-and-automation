# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000364
# Title:   VMware Cloud Foundation SDDC Manager must be configured to forward logs to a central log server.
# Severity:medium  CCI:CCI-001851  NIST:AU-4 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000364_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000364: source STIG control is manual/Not-Applicable. Review per meta.'
