# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000127
# Title:   The VMware Cloud Foundation Operations Apache HTTP service must enable Content Security Policy.
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFH-9X-000127:
  file.append:
    - name: /usr/lib/vmware-vcopssuite/utilities/conf/vcops-photon-apache.conf
    - text: '    Header set Content-Security-Policy "default-src https: wss: data: ''unsafe-inline'' ''unsafe-eval''; child-src *; worker-src ''self'' blob:"'

VCFH-9X-000127_step2:
  file.replace:
    - name: /usr/lib/vmware-vcopssuite/utilities/conf/vcops-photon-apache.conf
    - pattern: '(?!^#)(^\s*Header set Content-Security-Policy\s*)(.*)$'
    - repl: '\1"default-src https: wss: data: ''unsafe-inline'' ''unsafe-eval''; child-src *; worker-src ''self'' blob:"'
    - append_if_not_found: True
    - backup: False
