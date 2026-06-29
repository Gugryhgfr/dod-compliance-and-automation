# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000127
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must enable Content Security Policy.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000127:
  file.append:
    - name: /opt/vmware/config/apache-httpd/hcx-virtual-hosts.conf
    - text: '    Header set Content-Security-Policy "style-src ''self'' ''unsafe-inline''; font-src ''self'' data:; img-src ''self'' data:"'

VCFJ-9X-000127_step2:
  file.replace:
    - name: /opt/vmware/config/apache-httpd/hcx-virtual-hosts.conf
    - pattern: '(?!^#)(^\s*Header set Content-Security-Policy\s*)(.*)$'
    - repl: '\1"style-src ''self'' ''unsafe-inline''; font-src ''self'' data:; img-src ''self'' data:"'
    - append_if_not_found: True
    - backup: False
