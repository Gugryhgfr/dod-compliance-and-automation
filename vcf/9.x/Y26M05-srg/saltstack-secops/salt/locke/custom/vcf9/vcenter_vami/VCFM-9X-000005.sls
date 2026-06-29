# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFM-9X-000005
# Title:   The VMware Cloud Foundation vCenter VAMI Lighttpd service must generate information to monitor remote access.
# Severity:medium  CCI:CCI-000067  NIST:AC-17 (1)
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFM-9X-000005:
  file.append:
    - name: /etc/lighttpd/modules.conf
    - text: 'server.modules += ("mod_accesslog")'
