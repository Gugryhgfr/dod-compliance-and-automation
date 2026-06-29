# -*- coding: utf-8 -*-
# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).
# Control: VCFJ-9X-000007
# Title:   The VMware Cloud Foundation Operations HCX Apache HTTP service must generate, at a minimum, log records for system 
# Severity:medium  CCI:CCI-000131,CCI-000132,CCI-000133,CCI-000134,CCI-000169,CCI-001487,CCI-001889,CCI-001890  NIST:AU-12 a,AU-3 b,AU-3 c,AU-3 d,AU-3 e,AU-3 f,AU-8 b
#
# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)
# and remediates when applied. See the matching .meta file for full check/fix guidance.
# Tier: ansible-native

VCFJ-9X-000007:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: LoadModule log_config_module /usr/lib/httpd/modules/mod_log_config.so

VCFJ-9X-000007_step2:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LoadModule\s*)(log_config_module\s?)(.*)$'
    - repl: \1\2/usr/lib/httpd/modules/mod_log_config.so
    - append_if_not_found: True
    - backup: False

VCFJ-9X-000007_step3:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LogFormat\s*)(.*)(common)$'
    - repl: ''
    - backup: False

VCFJ-9X-000007_step4:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: 'LogFormat {% raw %}"%h %l %u %t \"%r\" %>s %b %{ms}T" {% endraw %}common'

VCFJ-9X-000007_step5:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LogFormat\s*)(.*)(common)$'
    - repl: '\1{% raw %}"%h %l %u %t \"%r\" %>s %b %{ms}T" {% endraw %}\3'
    - append_if_not_found: True
    - backup: False

VCFJ-9X-000007_step6:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LogFormat\s*)(.*)(combined)$'
    - repl: ''
    - backup: False

VCFJ-9X-000007_step7:
  file.append:
    - name: /etc/httpd/conf/httpd.conf
    - text: 'LogFormat {% raw %}"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" {% endraw %}combined'

VCFJ-9X-000007_step8:
  file.replace:
    - name: /etc/httpd/conf/httpd.conf
    - pattern: '(?!^#)(^\s*LogFormat\s*)(.*)(combined)$'
    - repl: '\1{% raw %}"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" {% endraw %}\3'
    - append_if_not_found: True
    - backup: False
