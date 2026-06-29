# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFC-9X-000121
# Title:   The VMware Cloud Foundation SDDC Manager PostgreSQL service must off-load audit data to a separate log management f
# Severity:medium  CCI:CCI-001851,CCI-003821,CCI-003831  NIST:AU-4 (1),AU-6 (4),AU-9 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFC-9X-000121:
  file.managed:
    - name: /etc/rsyslog.d/stig-services-postgres.conf
    - mode: 0640
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFC-9X-000121'
    - template: jinja
