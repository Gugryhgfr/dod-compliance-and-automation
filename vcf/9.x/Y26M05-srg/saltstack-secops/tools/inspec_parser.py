"""Parse VMware STIG InSpec control files into structured records."""
import os
import re
import glob

# A control block starts with `control 'ID' do` at column 0 and ends with `end` at column 0.
CONTROL_START = re.compile(r"^control\s+(['\"])([A-Za-z0-9\-_]+)\1\s+do\s*$")


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def split_controls(text):
    """Yield (control_id, body_lines) for each top-level control block in a file."""
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        m = CONTROL_START.match(lines[i])
        if not m:
            i += 1
            continue
        cid = m.group(2)
        body = []
        i += 1
        # Capture until a line that is exactly `end` (col 0, no leading space).
        while i < n and lines[i].rstrip() != "end":
            body.append(lines[i])
            i += 1
        i += 1  # skip the closing end
        yield cid, body


def _read_string_literal(s, start):
    """Read a Ruby string literal beginning at index `start` (which points at a quote).
    Handles ' and " with backslash escapes. Returns (value, index_after_close)."""
    quote = s[start]
    out = []
    i = start + 1
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            # In double quotes, \" -> ", \\ -> \, \n stays literal text in STIG content.
            if nxt in ('"', "'", "\\"):
                out.append(nxt)
                i += 2
                continue
            out.append(c)
            i += 1
            continue
        if c == quote:
            return "".join(out), i + 1
        out.append(c)
        i += 1
    return "".join(out), i


def _find_call(body_text, name):
    """Find `name <args...>` and return the start index just after the name token."""
    # name may be like desc, title, impact. Match as a word at a line (any indent) or after `desc 'x',`.
    pat = re.compile(r"(?m)^\s*%s\b" % re.escape(name))
    return pat


def _clean(txt):
    # Normalize whitespace in STIG narrative: collapse runs of spaces, strip lines.
    lines = [ln.strip() for ln in txt.replace("\r", "").split("\n")]
    # drop leading/trailing empties
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def parse_desc_fields(body_text):
    """Extract the bare desc, and keyed desc 'check'/'fix'/'rationale'."""
    fields = {"desc": "", "check": "", "fix": "", "rationale": ""}
    # keyed: desc 'key', "value"  OR  desc 'key', 'value'
    for key in ("check", "fix", "rationale"):
        m = re.search(r"desc\s+(['\"])%s\1\s*,\s*" % key, body_text)
        if m:
            val, _ = _read_string_literal(body_text, m.end())
            fields[key] = _clean(val)
    # bare desc: `desc 'value'` or `desc "value"` NOT followed by a comma-key.
    for m in re.finditer(r"(?m)^\s*desc\s+(['\"])", body_text):
        qi = m.end() - 1
        # ensure not a keyed desc (i.e., the char sequence isn't desc 'check',)
        val, after = _read_string_literal(body_text, qi)
        # if immediately followed by a comma it's a keyed desc; skip
        rest = body_text[after:after + 3]
        if rest.lstrip().startswith(","):
            continue
        fields["desc"] = _clean(val)
        break
    return fields


def parse_simple(body_text, name):
    m = re.search(r"(?m)^\s*%s\s+(['\"])" % re.escape(name), body_text)
    if m:
        val, _ = _read_string_literal(body_text, m.end() - 1)
        return _clean(val)
    return ""


def parse_impact(body_text):
    m = re.search(r"(?m)^\s*impact\s+([0-9.]+)", body_text)
    return float(m.group(1)) if m else None


def parse_tag(body_text, tag):
    m = re.search(r"tag\s+%s:\s*(['\"])(.*?)\1" % re.escape(tag), body_text)
    return m.group(2) if m else ""


def parse_tag_list(body_text, tag):
    m = re.search(r"tag\s+%s:\s*\[(.*?)\]" % re.escape(tag), body_text, re.S)
    if not m:
        return []
    return re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))


def audit_body(body_text):
    """Return the InSpec audit logic: everything from the first `describe` or assignment
    after the metadata tags."""
    # Heuristic: find first line that begins a describe/vmhosts/powercli/assignment after tags.
    idx = None
    for m in re.finditer(r"(?m)^\s*(describe\b|powercli_command\b|\w+\s*=\s|command\(|unless\b|if\b)", body_text):
        idx = m.start()
        break
    return body_text[idx:].strip() if idx is not None else ""


def component_from_path(path, inspec_root):
    rel = os.path.relpath(path, inspec_root)
    parts = rel.split(os.sep)
    baseline = parts[0]
    # subpath = dirs between baseline and 'controls'
    try:
        ci = parts.index("controls")
    except ValueError:
        ci = len(parts) - 1
    sub = parts[1:ci]
    return baseline, "/".join(sub)


def parse_all(inspec_root):
    records = {}  # id -> record (dedup, first canonical wins)
    files = sorted(glob.glob(os.path.join(inspec_root, "**", "controls", "*.rb"), recursive=True))
    for path in files:
        text = _read(path)
        baseline, sub = component_from_path(path, inspec_root)
        for cid, body in split_controls(text):
            body_text = "\n".join(body)
            rec = {
                "id": cid,
                "title": parse_simple(body_text, "title"),
                "impact": parse_impact(body_text),
                "severity": parse_tag(body_text, "severity"),
                "gtitle": parse_tag(body_text, "gtitle"),
                "gid": parse_tag(body_text, "gid"),
                "rid": parse_tag(body_text, "rid"),
                "stig_id": parse_tag(body_text, "stig_id") or cid,
                "cci": parse_tag_list(body_text, "cci"),
                "nist": parse_tag_list(body_text, "nist"),
                "baseline": baseline,
                "subcomponent": sub,
                "source": os.path.relpath(path, inspec_root),
                "audit": audit_body(body_text),
            }
            rec.update(parse_desc_fields(body_text))
            # Prefer a record that actually has audit logic / richer content if dup.
            if cid not in records:
                records[cid] = rec
            else:
                old = records[cid]
                if len(rec["audit"]) > len(old["audit"]):
                    records[cid] = rec
    return records


if __name__ == "__main__":
    import sys
    root = sys.argv[1]
    recs = parse_all(root)
    print("TOTAL unique controls:", len(recs))
    # show a few
    for cid in list(recs)[:2]:
        r = recs[cid]
        print("=" * 60)
        for k in ("id", "title", "severity", "stig_id", "cci", "nist", "baseline", "subcomponent"):
            print(f"{k}: {r[k]}")
        print("desc:", r["desc"][:120])
        print("check:", r["check"][:160])
        print("fix:", r["fix"][:160])
        print("audit[:200]:", r["audit"][:200])
    # component histogram
    from collections import Counter
    comp = Counter((r["baseline"], r["subcomponent"]) for r in recs.values())
    print("\nCOMPONENTS:")
    for (b, s), c in sorted(comp.items()):
        print(f"  {c:4d}  {b} :: {s}")
