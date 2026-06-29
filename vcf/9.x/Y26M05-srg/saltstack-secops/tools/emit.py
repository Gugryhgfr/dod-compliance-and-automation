"""Emit SaltStack SecOps custom-content .sls (Salt state) and .meta (YAML) for a STIG control."""
import re
import json

from ansible_parser import resolve_vars

# Modules we translate into native Salt states.
REMEDIATION_MODULES = {
    "ansible.builtin.lineinfile", "ansible.builtin.replace", "ansible.builtin.file",
    "ansible.builtin.copy", "ansible.builtin.template", "ansible.builtin.command",
    "ansible.builtin.shell", "ansible.builtin.systemd", "ansible.builtin.service",
    "ansible.posix.sysctl", "community.general.pamd", "community.general.pam_limits",
    "ansible.builtin.apt", "ansible.builtin.uri", "ansible.builtin.blockinfile",
    "community.general.timezone",
}

# OS grain (osfinger) per InSpec baseline/subcomponent group.
PHOTON = ["VMware Photon OS-5"]


# ----------------------------------------------------------------------------
# Salt state rendering helpers
# ----------------------------------------------------------------------------
def _yaml_scalar(v):
    """Render a scalar for a Salt state value, quoting when needed."""
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "":
        return "''"
    # Use single quotes; escape embedded single quotes by YAML doubling.
    needs_quote = bool(re.search(r"[:#\{\}\[\]&\*!\|>'\"%@`,]", s)) or s.strip() != s \
        or s[0] in "-?@`" or "\n" in s
    if "\n" in s:
        # block scalar
        indented = "\n".join("        " + ln for ln in s.split("\n"))
        return "|\n" + indented
    if needs_quote:
        return "'" + s.replace("'", "''") + "'"
    return s


def render_state(state_id, module_func, args):
    """args: list of (key, value) tuples. Returns Salt SLS text for one state declaration."""
    lines = ["{}:".format(_yaml_scalar(state_id) if re.search(r"[:#]", state_id) else state_id)]
    lines.append("  {}:".format(module_func))
    for k, v in args:
        if v is None:
            continue
        rv = _yaml_scalar(v)
        if rv.startswith("|\n"):
            lines.append("    - {}: {}".format(k, rv))
        else:
            lines.append("    - {}: {}".format(k, rv))
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# InSpec audit -> shell guard (used for `unless` on cmd.run)
# ----------------------------------------------------------------------------
def _pcre(s):
    return s.replace("'", "'\"'\"'")


def derive_audit_guard(rec):
    """Best-effort shell command that exits 0 when the host is ALREADY compliant.
    Returns (guard_or_None, kind)."""
    audit = rec.get("audit", "")
    if not audit:
        return None, "none"

    # kernel_parameter('k') { its('value') { should eq N } }
    m = re.search(r"kernel_parameter\((['\"])([^'\"]+)\1\)", audit)
    if m:
        key = m.group(2)
        mv = re.search(r"should\s+eq\s+(['\"]?)([\w.\-]+)\1", audit)
        if mv:
            return '[ "$(sysctl -n {0} 2>/dev/null)" = "{1}" ]'.format(key, mv.group(2)), "kernel_parameter"

    # file('P') ... its('content') { should match /RE/ }
    mf = re.search(r"(?:describe\s+)?file\((['\"])([^'\"]+)\1\)", audit)
    if mf:
        path = mf.group(2)
        mc = re.search(r"its\(\s*'content'\s*\).*?match\s+/(.+?)/", audit, re.S)
        if mc:
            return "grep -Pqz '{0}' '{1}'".format(_pcre(mc.group(1)), path), "file_content"
        if re.search(r"should\s+exist", audit):
            return "test -e '{0}'".format(path), "file_exist"
        msh = re.search(r"its\(\s*'content'\s*\)\s*\{\s*should\s+match\s+(['\"])(.+?)\1", audit)
        if msh:
            return "grep -Pqz '{0}' '{1}'".format(_pcre(msh.group(2)), path), "file_content"

    # command('CMD') ... its('stdout') { should match /RE/ }   OR exit_status eq 0
    mc = re.search(r"command\((['\"])(.+?)\1\)", audit, re.S)
    if mc:
        cmd = mc.group(2)
        mr = re.search(r"its\(\s*'stdout'\s*\).*?match\s+/(.+?)/", audit, re.S)
        if mr:
            return "{0} 2>/dev/null | grep -Pq '{1}'".format(cmd, _pcre(mr.group(1))), "command_stdout"
        ms = re.search(r"its\(\s*'stdout(?:\.strip)?'\s*\)\s*\{\s*should\s+(?:eq|cmp)\s+(['\"])(.+?)\1", audit)
        if ms:
            return "[ \"$({0} 2>/dev/null)\" = \"{1}\" ]".format(cmd, ms.group(2)), "command_eq"
        if re.search(r"its\(\s*'exit_status'\s*\).*?eq\s+0", audit, re.S):
            return cmd, "command_rc"

    return None, "none"


# ----------------------------------------------------------------------------
# PowerCLI extraction (API controls: ESX / VM / vCenter / NSX)
# ----------------------------------------------------------------------------
def extract_powercli(rec):
    """Pull the audit (Get-) and remediation (Set-) PowerCLI lines from check/fix text."""
    def grab(text):
        cmds = []
        for ln in text.split("\n"):
            ln = ln.strip()
            if not ln:
                continue
            if re.match(r"(Get|Set|Add|Remove|New|Disable|Enable|Stop|Start|Update|Move|Restart)-[A-Za-z]", ln):
                cmds.append(ln)
            elif re.match(r"\$\w+\s*=", ln) and re.search(r"(Get|Set)-", ln):
                cmds.append(ln)
            elif re.match(r"esxcli\b", ln) or re.search(r"\|\s*esxcli", ln):
                cmds.append(ln)
        return cmds
    audit_cmds = grab(rec.get("check", ""))
    fix_cmds = grab(rec.get("fix", ""))
    remediate = next((c for c in fix_cmds if re.search(r"(Set|Disable|Enable|New|Remove|Add|Update|Move|Restart)-", c)
                      or re.search(r"esxcli\b.*\bset\b", c)), None)
    if not remediate and fix_cmds:
        remediate = fix_cmds[0]
    audit = next((c for c in audit_cmds if "Get-" in c or re.search(r"esxcli\b.*\bget\b|esxcli\b.*\blist\b", c)), None)
    if not audit and audit_cmds:
        audit = audit_cmds[0]
    return audit, remediate


# ----------------------------------------------------------------------------
# Ansible action -> Salt state(s)
# ----------------------------------------------------------------------------
def _rv(v, varmap):
    return resolve_vars(v, varmap) if isinstance(v, str) else v


def _is_readonly_cmd(cmd):
    """True if a command only reads/queries state (so it should not be a remediation step)."""
    c = cmd.strip()
    # strip common shell prologues that precede the real command
    c = re.sub(r"^(set\s+-o\s+pipefail|set\s+-e|set\s+-eu?o?\s*pipefail)\s*[;&]?\s*", "", c).strip()
    # writes always count as remediation
    if re.search(r"\bALTER\b|\bUPDATE\b|\bINSERT\b|\bCREATE\b|\bGRANT\b|\bREVOKE\b|\bSET\b", c, re.I) \
            and not re.search(r"\bshow\b", c, re.I):
        return False
    if re.search(r"\bsysctl\b", c) and not re.search(r"\bsysctl\b.*(-w|=)", c):
        return True  # sysctl read (no -w / =)
    if re.match(r"(?i)^(su\s+-\s+\S+\s+-c\s+['\"].*?(show|select)\b)", c) and not re.search(r"(?i)\balter\b", c):
        return True
    if re.search(r"(?i)\bselect\b.+\bfrom\b", c) and not re.search(r"(?i)\b(alter|update|insert|create)\b", c):
        return True
    if re.match(r"^(systemctl\s+(status|is-|show)|rpm\s+-q|dpkg\s+-l|dpkg\s+-s|grep\b|egrep\b|cat\b|"
                r"stat\b|test\b|\[\s|ls\b|find\b|awk\b|sed\s+-n|echo\b|tdnf\s+list|apt\s+list|"
                r"head\b|tail\b|wc\b|cut\b|sort\b|uniq\b|which\b|command\s+-v|getent\b|"
                r"/sbin/sysctl|/usr/sbin/sysctl)\b", c):
        return True
    return False


def _pkg_from_cmd(cmd):
    """Map a package-manager shell command to ('pkg.installed'|'pkg.removed', [names])."""
    c = re.sub(r"^(set\s+-o\s+pipefail\s*[;&]?\s*)", "", cmd).strip()
    m = re.match(r"^(?:/usr/bin/)?(tdnf|dnf|yum|apt|apt-get|rpm)\s+(.*)$", c)
    if not m:
        return None
    rest = m.group(2)
    if re.search(r"\b(install|-i)\b", rest):
        func = "pkg.installed"
    elif re.search(r"\b(remove|erase|purge)\b", rest):
        func = "pkg.removed"
    else:
        return None
    # strip flags/options, keep package tokens
    toks = [t for t in re.split(r"\s+", rest)
            if not t.startswith("-") and t not in ("install", "remove", "erase", "purge", "y")]
    toks = [t for t in toks if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$", t)]
    if not toks:
        return None
    return func, toks


def _action_is_readonly(action):
    """An Ansible command/shell with changed_when:false is a check, not a remediation."""
    cw = action.get("changed_when")
    if cw is False or (isinstance(cw, str) and cw.strip().lower() in ("false", "no")):
        return True
    return False


def _psql_guard(cmd):
    """For 'ALTER SYSTEM SET <param> = <val>' build a SHOW-based unless guard."""
    m = re.search(r"ALTER\s+SYSTEM\s+SET\s+([A-Za-z0-9_.]+)\s*=\s*'?([^';\"]+)'?", cmd)
    if not m:
        return None
    param, val = m.group(1), m.group(2).strip()
    # reuse the psql invocation prefix up to the -c argument
    pm = re.search(r"^(su\s+-\s+\S+\s+-c\s+[\"'].*?-A\s+-t\s+-c)\b", cmd)
    if pm:
        prefix = pm.group(1)
        return "{0} \\\"SHOW {1}\\\"\" | grep -qi '{2}'".format(prefix, param, re.escape(val))
    return "echo check | grep -q '{0}'  # verify {1}={2} manually".format(re.escape(val), param, val)


def _expected_value(set_cmd):
    """Pull the target value from a PowerCLI Set-* / -Value argument for an audit comparison."""
    m = re.search(r"-Value[:\s]+\$?(['\"]?)([\w.]+)\1", set_cmd)
    if not m:
        return None
    v = m.group(2)
    if v.lower() in ("true", "false"):
        return "$" + v.lower()
    if re.match(r"^-?\d+$", v):
        return v
    return "'" + v + "'"


def is_manual_by_design(rec):
    """True if the source InSpec control is itself a manual/Not-Applicable check."""
    a = rec.get("audit", "")
    has_real = any(k in a for k in (
        "powercli_command", "command(", "kernel_parameter(", "parse_config_file",
        "postgres_session", "describe file", "describe service", "describe package",
        "http(", "json(", "nginx", "httpd"))
    low = a.lower()
    flag = ("must be reviewed manually" in low or "is n/a" in low.replace("n/a", "n/a")
            or "is N/A" in a or "not deployed" in a or "this check is manual" in low)
    return flag and not has_real


def translate_action(cid, idx, action, varmap):
    """Translate one Ansible action dict to a list of (suffix, module_func, args) Salt states.
    Returns [] if not translatable."""
    mod = action["module"]
    a = {k: _rv(v, varmap) for k, v in action["args"].items()}
    out = []

    if mod == "ansible.builtin.lineinfile":
        path = a.get("path") or a.get("dest")
        line = a.get("line", "")
        regexp = a.get("regexp")
        state = a.get("state", "present")
        if not path:
            return []
        if state == "absent":
            out.append(("", "file.replace", [
                ("name", path), ("pattern", regexp or re.escape(str(line))),
                ("repl", ""), ("backup", False)]))
        else:
            if regexp:
                out.append(("", "file.replace", [
                    ("name", path), ("pattern", regexp), ("repl", line),
                    ("append_if_not_found", True), ("backup", False)]))
            else:
                out.append(("", "file.append", [("name", path), ("text", line)]))
        return out

    if mod == "ansible.builtin.replace":
        path = a.get("path") or a.get("dest")
        out.append(("", "file.replace", [
            ("name", path), ("pattern", a.get("regexp", "")),
            ("repl", a.get("replace", "")), ("backup", False)]))
        return out

    if mod == "ansible.builtin.blockinfile":
        path = a.get("path") or a.get("dest")
        out.append(("", "file.blockreplace", [
            ("name", path), ("content", a.get("block", "")),
            ("append_if_not_found", True), ("backup", False)]))
        return out

    if mod == "ansible.posix.sysctl":
        out.append(("", "sysctl.present", [
            ("name", a.get("name")), ("value", a.get("value")),
            ("config", a.get("sysctl_file", "/etc/sysctl.conf"))]))
        return out

    if mod in ("ansible.builtin.systemd", "ansible.builtin.service"):
        name = a.get("name")
        st = a.get("state", "started")
        enabled = a.get("enabled")
        func = "service.running" if st in ("started", "running", None) else "service.dead"
        args = [("name", name)]
        if enabled is not None:
            args.append(("enable", str(enabled).lower() in ("true", "yes", "1", "True")))
        out.append(("", func, args))
        return out

    if mod == "community.general.pam_limits":
        domain = a.get("domain", "*")
        ltype = a.get("limit_type", "hard")
        item = a.get("limit_item", "")
        value = a.get("value", "")
        path = a.get("dest", "/etc/security/limits.conf")
        pattern = r"^\s*{0}\s+{1}\s+{2}\s+.*$".format(re.escape(str(domain)), re.escape(str(ltype)), re.escape(str(item)))
        repl = "{0}\t{1}\t{2}\t{3}".format(domain, ltype, item, value)
        out.append(("", "file.replace", [
            ("name", path), ("pattern", pattern), ("repl", repl),
            ("append_if_not_found", True), ("backup", False)]))
        return out

    if mod == "community.general.pamd":
        name = a.get("name", "")
        path = "/etc/pam.d/{0}".format(name)
        mtype = a.get("type", "")
        module_path = a.get("module_path", "")
        margs = a.get("module_arguments", "")
        # best-effort: ensure the module line carries the desired argument
        argkey = str(margs).split("=")[0] if "=" in str(margs) else str(margs)
        pattern = r"^({0}\s+.*{1}).*$".format(re.escape(str(mtype)), re.escape(str(module_path)))
        out.append(("", "file.replace", [
            ("name", path),
            ("pattern", r"^(\s*{0}\s+\S+\s+{1}\b)(.*)$".format(re.escape(str(mtype)), re.escape(str(module_path)))),
            ("repl", r"\1 {0}".format(margs)),
            ("append_if_not_found", False), ("backup", False)]))
        return out

    if mod in ("ansible.builtin.copy", "ansible.builtin.template"):
        dest = a.get("dest")
        args = [("name", dest)]
        if a.get("mode"):
            args.append(("mode", a.get("mode")))
        if a.get("owner"):
            args.append(("user", a.get("owner")))
        if a.get("group"):
            args.append(("group", a.get("group")))
        # content source not portable from the Ansible role; require salt:// source via pillar
        args.append(("source", "salt://vcf9/files/{0}".format(cid)))
        if mod == "ansible.builtin.template":
            args.append(("template", "jinja"))
        out.append(("", "file.managed", args))
        return out

    if mod == "ansible.builtin.file":
        path = a.get("path") or a.get("dest")
        st = a.get("state", "file")
        if st == "directory":
            args = [("name", path)]
            for k, sk in (("mode", "mode"), ("owner", "user"), ("group", "group")):
                if a.get(k):
                    args.append((sk, a.get(k)))
            out.append(("", "file.directory", args))
        elif st == "absent":
            out.append(("", "file.absent", [("name", path)]))
        else:
            args = [("name", path), ("replace", False), ("create", True)]
            for k, sk in (("mode", "mode"), ("owner", "user"), ("group", "group")):
                if a.get(k):
                    args.append((sk, a.get(k)))
            out.append(("", "file.managed", args))
        return out

    if mod == "ansible.builtin.apt":
        name = a.get("name")
        st = a.get("state", "present")
        func = "pkg.removed" if st in ("absent", "removed") else "pkg.installed"
        out.append(("", func, [("name", name)]))
        return out

    if mod == "community.general.timezone":
        out.append(("", "timezone.system", [("name", a.get("name"))]))
        return out

    if mod in ("ansible.builtin.command", "ansible.builtin.shell"):
        # A registered check step (changed_when: false) is not a remediation.
        if _action_is_readonly(action):
            return out
        cmd = a.get("cmd") or a.get("_raw") or a.get("_raw_params") or a.get("argv")
        if isinstance(cmd, list):
            cmd = " ".join(str(x) for x in cmd)
        if not cmd and len(a) == 1:
            cmd = list(a.values())[0]
        if isinstance(cmd, str):
            cmd = re.sub(r"\s+", " ", cmd).strip()
        if not cmd:
            return out
        # Skip pure read/get/show commands - they do not remediate.
        if _is_readonly_cmd(cmd):
            return out
        # Package-manager commands -> idempotent native pkg states (audit-correct).
        pk = _pkg_from_cmd(cmd)
        if pk:
            func, pkgs = pk
            out.append(("", func, [("name", pkgs[0])] if len(pkgs) == 1
                        else [("pkgs", "[" + ", ".join(pkgs) + "]")]))
            return out
        args = [("name", cmd)]
        guard = _psql_guard(cmd)
        if guard:
            args.append(("unless", guard))
        out.append(("cmd", "cmd.run", args))
        return out

    if mod == "ansible.builtin.uri":
        url = a.get("url", "")
        method = str(a.get("method", "GET")).upper()
        if method == "GET":   # read-only API call: a check, not a remediation
            return out
        body = a.get("body")
        curl = "curl -ksS -X {0} '{1}'".format(method, url)
        if body:
            curl += " -H 'Content-Type: application/json' -d '{0}'".format(
                json.dumps(body) if isinstance(body, (dict, list)) else str(body))
        out.append(("api", "cmd.run", [("name", curl)]))
        return out

    return []


# ----------------------------------------------------------------------------
# Top-level: build .sls text for a control
# ----------------------------------------------------------------------------
def build_sls(rec, remediation_actions, varmap):
    cid = rec["id"]
    header = [
        "# -*- coding: utf-8 -*-",
        "# SaltStack SecOps custom check (generated from VMware STIG InSpec + Ansible content).",
        "# Control: {0}".format(cid),
        "# Title:   {0}".format(rec["title"][:115]),
        "# Severity:{0}  CCI:{1}  NIST:{2}".format(
            rec.get("severity", ""), ",".join(rec.get("cci", [])), ",".join(rec.get("nist", []))),
        "#",
        "# SecOps model: this state is assessed with test=True (a predicted change == non-compliant)",
        "# and remediates when applied. See the matching .meta file for full check/fix guidance.",
    ]
    tier = "manual"
    body_states = []
    unguarded_cmd = False

    # 1) Prefer real Ansible remediation translated to native Salt.
    actions = [act for act in remediation_actions if act["module"] in REMEDIATION_MODULES]
    translated = []
    for act in actions:
        translated += translate_action(cid, None, act, varmap)
    if translated:
        tier = "ansible-native"
        seen = set()
        n = 0
        for suffix, func, args in translated:
            n += 1
            sid = cid if (suffix == "" and n == 1) else "{0}_{1}".format(cid, suffix or "step{0}".format(n))
            if sid in seen:
                sid = "{0}_{1}".format(sid, n)
            seen.add(sid)
            # attach an audit guard to cmd.run steps when derivable and not already guarded
            if func == "cmd.run":
                has_unless = any(k == "unless" for k, _ in args)
                if not has_unless:
                    guard, _ = derive_audit_guard(rec)
                    if guard:
                        args = list(args) + [("unless", guard)]
                    else:
                        unguarded_cmd = True
            body_states.append(render_state(sid, func, args))

    # 1b) Source control is itself a manual / Not-Applicable check.
    if not body_states and is_manual_by_design(rec):
        tier = "manual-by-design"
        body_states.append(render_state(
            cid + "_manual", "test.succeed_with_changes",
            [("name", "{0}: source STIG control is manual/Not-Applicable. Review per meta.".format(cid))]))

    # 2) No Ansible: try a self-contained cmd.run with an InSpec-derived audit guard.
    if not body_states:
        guard, kind = derive_audit_guard(rec)
        if guard:
            # Remediation from STIG fix text: take the first command-looking line.
            remediate_cmd = _first_command(rec.get("fix", ""))
            tier = "inspec-guarded"
            if remediate_cmd:
                body_states.append(render_state(cid, "cmd.run", [
                    ("name", remediate_cmd), ("unless", guard)]))
            else:
                # audit-only: report compliant/non-compliant, no automated fix available
                tier = "inspec-audit-only"
                body_states.append(render_state(cid, "cmd.run", [
                    ("name", "/bin/false  # no automated remediation; see meta fix"),
                    ("unless", guard)]))

    # 3) PowerCLI / API controls (ESX, VM, vCenter API, NSX).
    if not body_states:
        audit_pc, rem_pc = extract_powercli(rec)
        if audit_pc or rem_pc:
            tier = "powercli-proxy"
            header.append("#")
            header.append("# NOTE: API-managed control. Requires a PowerCLI-capable (proxy) minion with a")
            header.append("#       connection to vCenter/NSX. Connection is expected via pillar 'vcf_secops'.")
            connect = ("$null = Connect-VIServer -Server (salt_pillar vcenter) "
                       "-User (salt_pillar user) -Password (salt_pillar pass)")
            name_cmd = "pwsh -NoProfile -Command \"{0}\"".format((rem_pc or "Write-Output 'manual remediation required'").replace('"', '\\"'))
            states = [("name", name_cmd)]
            if audit_pc:
                exp = _expected_value(rem_pc or "")
                get_expr = audit_pc if audit_pc.strip().startswith("(") else "(" + audit_pc + ")"
                if exp is not None:
                    cond = "if(($v.Value -eq {0}) -or ($v -eq {0})){{exit 0}}else{{exit 1}}".format(exp)
                else:
                    cond = "if($v){exit 0}else{exit 1}"
                unless = "pwsh -NoProfile -Command \"$v={0}; {1}\"".format(get_expr.replace('"', '\\"'), cond)
                states.append(("unless", unless))
            body_states.append(
                "{% if salt['pillar.get']('vcf_secops:enable_powercli', False) %}\n"
                + render_state(cid, "cmd.run", states)
                + "\n{% else %}\n"
                + render_state(cid + "_manual", "test.succeed_with_changes",
                               [("name", "API control {0}: enable pillar vcf_secops:enable_powercli or review manually.".format(cid))])
                + "\n{% endif %}")

    # 4) Pure manual fallback.
    if not body_states:
        tier = "manual"
        body_states.append(render_state(
            cid + "_manual", "test.succeed_with_changes",
            [("name", "{0} requires manual review. See meta global_description / remediation.".format(cid))]))

    if unguarded_cmd:
        header.append("#")
        header.append("# WARNING: contains an unguarded cmd.run step (no on-host audit could be derived).")
        header.append("#          Under test=True this step always reports a pending change. Add an")
        header.append("#          'unless'/'onlyif' guard or an attestation to assess accurately.")
        tier = "ansible-native-unguarded"
    joined_body = "\n\n".join(body_states)
    if "<<" in joined_body:
        header.append("#")
        header.append("# WARNING: contains runtime placeholders (<<...>>) for Ansible loop items or Jinja")
        header.append("#          request-body templates that cannot be resolved statically. Supply these")
        header.append("#          values (pillar/template) before use - typically NSX/appliance REST bodies.")
    text = "\n".join(header) + "\n# Tier: {0}\n\n".format(tier) + joined_body + "\n"
    return text, tier


def _first_command(fix_text):
    """Extract a plausible shell command line from STIG fix narrative."""
    for ln in fix_text.split("\n"):
        s = ln.strip()
        if s.startswith("#"):
            s = s.lstrip("# ").strip()
        if not s:
            continue
        if re.match(r"^(systemctl|sysctl|chmod|chown|sed|echo|rm|mv|cp|useradd|usermod|"
                     r"groupadd|passwd|tdnf|apt|update-crypto-policies|auditctl|"
                     r"chage|gpasswd|setsebool|firewall-cmd|update-grub)\b", s):
            return s
    return None
