# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000206
# Title:   The Photon operating system must enforce a delay of at least four seconds between logon prompts following a failed 
# Severity:medium  CCI:CCI-000366  NIST:CM-6 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000206:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^auth\s+(required|requisite|\[default=die\])\s+pam_faillock\.so.*$'
    - repl: ''
    - backup: False

PHTN-50-000206_step2:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(auth\s+)\brequired\b(\s+pam_unix\.so\b.*)$'
    - repl: \1sufficient\2
    - backup: False

PHTN-50-000206_step3:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(\s*auth\s+\S+\s+pam_unix\.so\b)(.*)$'
    - repl: \1 preauth
    - append_if_not_found: False
    - backup: False

PHTN-50-000206_step4:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(\s*auth\s+\S+\s+pam_unix\.so\b)(.*)$'
    - repl: \1 authfail
    - append_if_not_found: False
    - backup: False

PHTN-50-000206_step5:
  file.replace:
    - name: /etc/pam.d/system-account
    - pattern: '^(\s*account\s+\S+\s+pam_faillock\.so\b)(.*)$'
    - repl: '\1 '
    - append_if_not_found: False
    - backup: False

PHTN-50-000206_step6:
  file.replace:
    - name: /etc/pam.d/system-account
    - pattern: '^(\s*account\s+\S+\s+pam_unix\.so\b)(.*)$'
    - repl: '\1 '
    - append_if_not_found: False
    - backup: False

PHTN-50-000206_step7:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(\s*auth\s+\S+\s+pam_faildelay\.so\b)(.*)$'
    - repl: '\1 '
    - append_if_not_found: False
    - backup: False

PHTN-50-000206_step8:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^#?auth\s+(required|requisite|optional)\s+pam_faildelay\.so\sdelay=4000000.*$'
    - repl: auth       optional pam_faildelay.so delay=4000000
    - append_if_not_found: True
    - backup: False

PHTN-50-000206_step9:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(\s*auth\s+\S+\s+pam_deny\.so\b)(.*)$'
    - repl: '\1 '
    - append_if_not_found: False
    - backup: False

PHTN-50-000206_step10:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^#?\s*auth\s+(required|requisite|optional)\s+pam_deny\.so\b.*$'
    - repl: auth       required pam_deny.so
    - append_if_not_found: True
    - backup: False
