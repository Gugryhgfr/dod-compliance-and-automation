# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFA-9X-000054
# Title:   VMware Cloud Foundation must use multifactor authentication for access to privileged accounts.
# Severity:medium  CCI:CCI-000166,CCI-000764,CCI-000765,CCI-000766,CCI-000804,CCI-003627,CCI-004046,CCI-004047  NIST:AC-2 (3) (a),AU-10,IA-2,IA-2 (1),IA-2 (2),IA-2 (6) (a),IA-2 (6) (b),IA-8
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: manual-by-design

VCFA-9X-000054_manual:
  test.succeed_with_changes:
    - name: 'VCFA-9X-000054: source STIG control is manual/Not-Applicable. Review per meta.'
