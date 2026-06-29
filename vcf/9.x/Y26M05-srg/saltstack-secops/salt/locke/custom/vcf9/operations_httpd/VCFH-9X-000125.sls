# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFH-9X-000125
# Title:   The VMware Cloud Foundation Operations Apache HTTP service must prevent rendering inside a frame or iframe on anoth
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFH-9X-000125:
  file.append:
    - name: /usr/lib/vmware-vcopssuite/utilities/conf/vcops-photon-apache.conf
    - text: '    Header set X-Frame-Options "SAMEORIGIN"'

VCFH-9X-000125_step2:
  file.replace:
    - name: /usr/lib/vmware-vcopssuite/utilities/conf/vcops-photon-apache.conf
    - pattern: '(?!^#)(^\s*Header set X-Frame-Options\s*)(.*)$'
    - repl: '\1"SAMEORIGIN"'
    - append_if_not_found: True
    - backup: False
