"""Index Ansible remediation tasks by STIG control ID, and build a variable map."""
import os
import re
import glob
import yaml

CID_RE = re.compile(r"^[A-Z]{3,5}-[0-9X]{2,3}-\d{3,}$")


def _safe_load_all(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    try:
        docs = list(yaml.safe_load_all(text))
        return docs
    except Exception:
        return []


def load_var_map(role_root):
    """Collect simple key:value vars from defaults/vars/group_vars for {{ }} resolution."""
    varmap = {}
    paths = []
    paths += glob.glob(os.path.join(role_root, "roles", "*", "defaults", "*.yml"))
    paths += glob.glob(os.path.join(role_root, "roles", "*", "vars", "*.yml"))
    paths += glob.glob(os.path.join(role_root, "group_vars", "*.yml"))
    paths += glob.glob(os.path.join(role_root, "vars", "*.yml"))
    for p in paths:
        for doc in _safe_load_all(p):
            if isinstance(doc, dict):
                for k, v in doc.items():
                    if isinstance(v, (str, int, float, bool)) and k not in varmap:
                        varmap[str(k)] = v
    return varmap


def resolve_vars(text, varmap, depth=4):
    """Resolve {{ var }} / {{ var | default(x) }} using varmap; leftovers -> literal token."""
    if not isinstance(text, str):
        return text
    # Resolve `{{ lookup('vars'|'env', 'X') }}` (and bare form) against the var map first.
    text = re.sub(r"\{\{\s*lookup\(\s*['\"](?:vars|env)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)\s*\}\}",
                  lambda m: str(varmap.get(m.group(1), "{{ " + m.group(1) + " }}")), text)
    text = re.sub(r"lookup\(\s*['\"](?:vars|env)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
                  lambda m: str(varmap.get(m.group(1), m.group(0))), text)
    pat = re.compile(r"\{\{\s*([a-zA-Z0-9_\.]+)(\s*\|\s*default\(([^)]*)\))?\s*\}\}")
    for _ in range(depth):
        changed = False

        def repl(m):
            nonlocal changed
            var = m.group(1)
            default = m.group(3)
            if var in varmap:
                changed = True
                return str(varmap[var])
            if default is not None:
                changed = True
                return default.strip().strip("'\"")
            return m.group(0)

        new = pat.sub(repl, text)
        if new == text or not changed:
            text = new
            break
        text = new
    # Any remaining {{ ... }} -> strip to inner token to keep Salt/Jinja from choking
    text = re.sub(r"\{\{\s*([^}]*?)\s*\}\}", lambda m: "<<" + m.group(1).split("|")[0].strip() + ">>", text)
    return text


def _flatten_tasks(tasks):
    """Yield task dicts, descending into block/rescue/always."""
    if not isinstance(tasks, list):
        return
    for t in tasks:
        if not isinstance(t, dict):
            continue
        yield t
        for key in ("block", "rescue", "always"):
            if key in t and isinstance(t[key], list):
                for sub in _flatten_tasks(t[key]):
                    yield sub


def _task_cids(task):
    """Return control IDs referenced by a task's tags or name."""
    cids = set()
    tags = task.get("tags")
    if isinstance(tags, str):
        tags = [tags]
    if isinstance(tags, list):
        for tg in tags:
            if isinstance(tg, str) and CID_RE.match(tg.strip()):
                cids.add(tg.strip())
    name = task.get("name", "")
    if isinstance(name, str):
        m = re.match(r"\.?([A-Z]{3,5}-[0-9X]{2,3}-\d{3,})", name.strip())
        if m:
            cids.add(m.group(1))
    return cids


MODULE_KEYS = (
    "ansible.builtin.lineinfile", "ansible.builtin.replace", "ansible.builtin.file",
    "ansible.builtin.copy", "ansible.builtin.template", "ansible.builtin.command",
    "ansible.builtin.shell", "ansible.builtin.systemd", "ansible.builtin.service",
    "ansible.posix.sysctl", "community.general.pamd", "community.general.pam_limits",
    "ansible.builtin.apt", "ansible.builtin.uri", "ansible.builtin.blockinfile",
    "ansible.builtin.lineinfile", "ansible.builtin.set_fact", "ansible.builtin.find",
    "ansible.builtin.stat", "ansible.builtin.slurp", "community.general.timezone",
)


def extract_action(task):
    """Return (module_name, args_dict) for the actionable module in a task, or None."""
    for k, v in task.items():
        if k in ("name", "tags", "when", "block", "rescue", "always", "register",
                 "changed_when", "failed_when", "with_items", "loop", "become",
                 "vars", "notify", "ignore_errors", "check_mode", "delegate_to",
                 "loop_control", "no_log", "until", "retries", "delay"):
            continue
        if k.startswith("ansible.") or k.startswith("community.") or "." in k:
            if isinstance(v, dict):
                return k, v
            if isinstance(v, str):  # free-form / folded scalar (command: > ...)
                return k, {"_raw": v.strip()}
        # bare module names too
        if k in ("lineinfile", "replace", "file", "copy", "template", "command",
                 "shell", "systemd", "service", "sysctl", "pamd", "pam_limits",
                 "apt", "uri", "blockinfile"):
            if isinstance(v, dict):
                return "ansible.builtin." + k, v
            if isinstance(v, str):
                return "ansible.builtin." + k, {"_raw": v.strip()}
    return None


def index_remediation(role_root):
    """Return {control_id: [ {name, module, args, when, loop, raw_task}, ... ]}."""
    idx = {}
    task_files = glob.glob(os.path.join(role_root, "roles", "*", "tasks", "*.yml"))
    for tf in task_files:
        docs = _safe_load_all(tf)
        for doc in docs:
            if not isinstance(doc, list):
                continue
            # Top-level tasks; each may carry a control id via tag/name and contain a block.
            for top in doc:
                if not isinstance(top, dict):
                    continue
                cids = _task_cids(top)
                # Gather actionable sub-tasks (the block) OR this task itself.
                subtasks = list(_flatten_tasks([top]))
                actions = []
                for st in subtasks:
                    act = extract_action(st)
                    if act:
                        mod, args = act
                        actions.append({
                            "name": st.get("name", ""),
                            "module": mod,
                            "args": args,
                            "when": st.get("when"),
                            "loop": st.get("loop") or st.get("with_items"),
                            "register": st.get("register"),
                            "changed_when": st.get("changed_when"),
                        })
                        # sub-task may also name a cid
                        cids |= _task_cids(st)
                if not cids:
                    continue
                for cid in cids:
                    idx.setdefault(cid, [])
                    # avoid duplicating identical action lists
                    for a in actions:
                        idx[cid].append(a)
                    idx[cid + "::source"] = os.path.relpath(tf, role_root)
    return idx


if __name__ == "__main__":
    import sys
    role_root = sys.argv[1]
    vm = load_var_map(role_root)
    print("vars loaded:", len(vm))
    idx = index_remediation(role_root)
    cids = [k for k in idx if not k.endswith("::source")]
    print("control ids with remediation:", len(cids))
    from collections import Counter
    modc = Counter()
    for cid in cids:
        for a in idx[cid]:
            modc[a["module"]] += 1
    print("modules:", modc.most_common())
    # show a sample
    for cid in ("PHTN-50-000007", "PHTN-50-000012", "PHTN-50-000067", "VCFA-9X-000019"):
        if cid in idx:
            print("=" * 50, cid, "src:", idx.get(cid + "::source"))
            for a in idx[cid]:
                print("  ", a["module"], "|", {k: (str(v)[:60]) for k, v in a["args"].items()})
