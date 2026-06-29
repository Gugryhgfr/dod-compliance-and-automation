# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: PHTN-50-000192
# Title:   The Photon operating system must be configured to use the pam_faillock.so module.
# Severity:medium  CCI:CCI-000044  NIST:AC-7 a
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

PHTN-50-000192:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^auth\s+(required|requisite|\[default=die\])\s+pam_faillock\.so.*$'
    - repl: ''
    - backup: False

PHTN-50-000192_step2:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(auth\s+)\brequired\b(\s+pam_unix\.so\b.*)$'
    - repl: \1sufficient\2
    - backup: False

PHTN-50-000192_step3:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(\s*auth\s+\S+\s+pam_unix\.so\b)(.*)$'
    - repl: \1 preauth
    - append_if_not_found: False
    - backup: False

PHTN-50-000192_step4:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(\s*auth\s+\S+\s+pam_unix\.so\b)(.*)$'
    - repl: \1 authfail
    - append_if_not_found: False
    - backup: False

PHTN-50-000192_step5:
  file.replace:
    - name: /etc/pam.d/system-account
    - pattern: '^(\s*account\s+\S+\s+pam_faillock\.so\b)(.*)$'
    - repl: '\1 '
    - append_if_not_found: False
    - backup: False

PHTN-50-000192_step6:
  file.replace:
    - name: /etc/pam.d/system-account
    - pattern: '^(\s*account\s+\S+\s+pam_unix\.so\b)(.*)$'
    - repl: '\1 '
    - append_if_not_found: False
    - backup: False

PHTN-50-000192_step7:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(\s*auth\s+\S+\s+pam_faildelay\.so\b)(.*)$'
    - repl: '\1 '
    - append_if_not_found: False
    - backup: False

PHTN-50-000192_step8:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^#?auth\s+(required|requisite|optional)\s+pam_faildelay\.so\sdelay=4000000.*$'
    - repl: auth       optional pam_faildelay.so delay=4000000
    - append_if_not_found: True
    - backup: False

PHTN-50-000192_step9:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^(\s*auth\s+\S+\s+pam_deny\.so\b)(.*)$'
    - repl: '\1 '
    - append_if_not_found: False
    - backup: False

PHTN-50-000192_step10:
  file.replace:
    - name: /etc/pam.d/system-auth
    - pattern: '^#?\s*auth\s+(required|requisite|optional)\s+pam_deny\.so\b.*$'
    - repl: auth       required pam_deny.so
    - append_if_not_found: True
    - backup: False
