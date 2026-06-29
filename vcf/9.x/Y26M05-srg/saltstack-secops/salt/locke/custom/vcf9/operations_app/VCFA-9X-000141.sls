# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000141
# Title:   VMware Cloud Foundation must be configured to forward vSphere logs to a central log server.
# Severity:medium  CCI:CCI-001348,CCI-001851  NIST:AU-4 (1),AU-9 (2)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000141_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000141: source STIG control is manual/Not-Applicable. Review per meta.'
