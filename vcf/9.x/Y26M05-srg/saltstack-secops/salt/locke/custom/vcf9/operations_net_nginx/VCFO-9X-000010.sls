# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFO-9X-000010
# Title:   The VMware Cloud Foundation Operations for Networks Platform NGINX server must produce log records containing suffi
# Severity:medium  CCI:CCI-000130,CCI-000131,CCI-000132,CCI-000133,CCI-000134,CCI-001487,CCI-001889  NIST:AU-3 a,AU-3 b,AU-3 c,AU-3 d,AU-3 e,AU-3 f,AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFO-9X-000010:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - mode: 0600
    - user: root
    - group: root
    - source: 'salt://vcf9/files/VCFO-9X-000010'
    - template: jinja
