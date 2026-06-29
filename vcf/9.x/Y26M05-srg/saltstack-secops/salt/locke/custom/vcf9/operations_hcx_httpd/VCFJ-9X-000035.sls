# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000035
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must constrain users and scripts running on behalf o
# Severity:medium  CCI:CCI-000381,CCI-001312  NIST:CM-7 a,SI-11 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000035:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^<Directory \/>\n)([\s\S]*?)(<\/Directory>)'
    - repl: |
        <Directory />
            AllowOverride none
            Require all denied
        </Directory>
    - backup: False
