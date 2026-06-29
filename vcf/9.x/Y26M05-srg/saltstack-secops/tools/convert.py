#!/usr/bin/env python3
"""
Convert VMware DoD VCF 9.x STIG content (InSpec audit + Ansible remediation)
into SaltStack SecOps Compliance custom-content (benchmarks + checks).

Output mirrors the layout produced by `secops_sdk init`:
    <out>/benchmarks/*.meta                         (custom benchmark definitions)
    <out>/salt/locke/custom/vcf9/<comp>/<ID>.sls    (Salt state: audit via test=True / remediate via apply)
    <out>/salt/locke/custom/vcf9/<comp>/<ID>.meta   (check metadata)
    <out>/sample_tests/...                           (docker test helpers)
    <out>/README.md
    <out>/COVERAGE.md                                (generated coverage report)
"""
import os
import sys
import re
import glob
from collections import Counter, defaultdict

from inspec_parser import parse_all
from ansible_parser import load_var_map, index_remediation
from emit import build_sls

# --------------------------------------------------------------------------
# Component / benchmark taxonomy. Key = (baseline, subcomponent) from InSpec.
# Value = (benchmark_id slug, display name, osfinger list)
# --------------------------------------------------------------------------
PHOTON = ["VMware Photon OS-5"]
APP = ["VMware Photon OS-5"]   # VCF appliances are Photon-based
NONE = []                       # API / proxy-managed (ESX, VM, vCenter API, NSX)

BENCH = {
    ("vmware-photon-5.0-stig-baseline", ""):
        ("vcf9_photon_5", "VMware Cloud Foundation 9.x - Photon OS 5.0", PHOTON),
    ("vmware-cloud-foundation-stig-baseline", "vsphere/esx"):
        ("vcf9_vsphere_esx", "VMware Cloud Foundation 9.x - vSphere ESX", NONE),
    ("vmware-cloud-foundation-stig-baseline", "vsphere/vm"):
        ("vcf9_vsphere_vm", "VMware Cloud Foundation 9.x - vSphere Virtual Machine", NONE),
    ("vmware-cloud-foundation-stig-baseline", "vsphere/vcenter"):
        ("vcf9_vsphere_vcenter", "VMware Cloud Foundation 9.x - vCenter Server", NONE),
    ("vmware-cloud-foundation-stig-baseline", "nsx/manager"):
        ("vcf9_nsx_manager", "VMware Cloud Foundation 9.x - NSX Manager", NONE),
    ("vmware-cloud-foundation-stig-baseline", "nsx/routing"):
        ("vcf9_nsx_routing", "VMware Cloud Foundation 9.x - NSX Routing (Tier-0/Tier-1)", NONE),
    ("vmware-cloud-foundation-stig-baseline", "automation"):
        ("vcf9_automation", "VMware Cloud Foundation 9.x - Automation", APP),
    ("vmware-cloud-foundation-stig-baseline", "operations"):
        ("vcf9_operations_app", "VMware Cloud Foundation 9.x - Operations (Application)", APP),
    ("vmware-cloud-foundation-stig-baseline", "opshcx"):
        ("vcf9_operations_hcx_app", "VMware Cloud Foundation 9.x - Operations HCX (Application)", APP),
    ("vmware-cloud-foundation-stig-baseline", "opsnet"):
        ("vcf9_operations_net_app", "VMware Cloud Foundation 9.x - Operations for Networks (Application)", APP),
    ("vmware-cloud-foundation-stig-baseline", "sddcmgr"):
        ("vcf9_sddc_manager_app", "VMware Cloud Foundation 9.x - SDDC Manager (Application)", APP),
    ("vmware-cloud-foundation-vcsa-stig-baseline", "envoy"):
        ("vcf9_vcenter_envoy", "VMware Cloud Foundation 9.x - vCenter Envoy", APP),
    ("vmware-cloud-foundation-vcsa-stig-baseline", "postgresql"):
        ("vcf9_vcenter_postgresql", "VMware Cloud Foundation 9.x - vCenter PostgreSQL", APP),
    ("vmware-cloud-foundation-vcsa-stig-baseline", "vami"):
        ("vcf9_vcenter_vami", "VMware Cloud Foundation 9.x - vCenter VAMI (Lighttpd)", APP),
    ("vmware-cloud-foundation-sddcmgr-stig-baseline", "nginx"):
        ("vcf9_sddc_manager_nginx", "VMware Cloud Foundation 9.x - SDDC Manager NGINX", APP),
    ("vmware-cloud-foundation-sddcmgr-stig-baseline", "postgresql"):
        ("vcf9_sddc_manager_postgresql", "VMware Cloud Foundation 9.x - SDDC Manager PostgreSQL", APP),
    ("vmware-cloud-foundation-operations-stig-baseline", "httpd"):
        ("vcf9_operations_httpd", "VMware Cloud Foundation 9.x - Operations Apache HTTP", APP),
    ("vmware-cloud-foundation-operations-stig-baseline", "postgresql"):
        ("vcf9_operations_postgresql", "VMware Cloud Foundation 9.x - Operations PostgreSQL", APP),
    ("vmware-cloud-foundation-operations-hcx-stig-baseline", "httpd"):
        ("vcf9_operations_hcx_httpd", "VMware Cloud Foundation 9.x - Operations HCX Apache HTTP", APP),
    ("vmware-cloud-foundation-operations-networks-stig-baseline", "nginx-platform"):
        ("vcf9_operations_net_nginx", "VMware Cloud Foundation 9.x - Operations for Networks NGINX", APP),
}


def bench_for(rec):
    key = (rec["baseline"], rec["subcomponent"])
    if key in BENCH:
        return BENCH[key]
    # fallback by prefix path slug
    slug = "vcf9_" + re.sub(r"[^a-z0-9]+", "_", (rec["baseline"] + "_" + rec["subcomponent"]).lower()).strip("_")
    return (slug, rec["baseline"] + " " + rec["subcomponent"], APP)


def comp_dir(rec):
    """Filesystem subdir under salt/locke/custom/vcf9 for this control's check."""
    slug, _, _ = bench_for(rec)
    return slug.replace("vcf9_", "")


# --------------------------------------------------------------------------
# YAML emitters (manual, to control SecOps meta formatting)
# --------------------------------------------------------------------------
def y_block(text, indent):
    pad = " " * indent
    if text is None:
        text = ""
    lines = str(text).replace("\r", "").split("\n")
    return "|-\n" + "\n".join(pad + ln if ln else "" for ln in lines)


def y_str(s):
    s = "" if s is None else str(s)
    if s == "":
        return "''"
    if re.search(r"[:#\[\]\{\}&\*!\|>'\"%@`]", s) or s != s.strip():
        return "'" + s.replace("'", "''") + "'"
    return s


def write_check_meta(path, rec, bench_slug, osfinger):
    L = []
    L.append("version: 1")
    L.append("display_name: " + y_str("{0} - {1}".format(rec["id"], rec["title"])[:240]))
    L.append("global_description: " + y_block(rec.get("desc", ""), 2))
    if osfinger:
        L.append("osfinger:")
        for o in osfinger:
            L.append("  - " + y_str(o))
    else:
        L.append("osfinger: []  # API/proxy-managed control; not tied to a minion OS grain")
    # cross references
    L.append("refs:")
    L.append("  disa_stig:")
    L.append("    - " + y_str(rec.get("stig_id", rec["id"])))
    if rec.get("gtitle"):
        L.append("  srg:")
        L.append("    - " + y_str(rec["gtitle"]))
    if rec.get("cci"):
        L.append("  cci:")
        for c in rec["cci"]:
            L.append("    - " + y_str(c))
    if rec.get("nist"):
        L.append("  nist:")
        for nv in rec["nist"]:
            L.append("    - " + y_str(nv))
    # benchmark section
    L.append("benchmark_id:")
    L.append("  {0}:".format(bench_slug))
    L.append("    type: custom")
    L.append("    desc: " + y_str(rec["title"][:240]))
    L.append("    control_id: " + y_str(rec.get("stig_id", rec["id"])))
    L.append("    scored: {0}".format("true" if (rec.get("impact") or 0) > 0 else "false"))
    L.append("    profile:")
    L.append("      - default")
    L.append("    information: " + y_block(rec.get("check", ""), 6))
    L.append("    rationale: " + y_block(rec.get("rationale") or rec.get("desc", ""), 6))
    L.append("    remediation: " + y_block(rec.get("fix", ""), 6))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def write_benchmark_meta(path, slug, display, desc, control_ids):
    L = []
    L.append("name: " + slug)
    L.append("display_name: " + y_str(display))
    L.append("desc: " + y_str(desc))
    L.append("version: '1'")
    L.append("authority: custom")
    L.append("reference: " + y_str("VMware Cloud Foundation 9.x STIG Readiness Guide (Y26M05)"))
    L.append("ids:")
    for cid in sorted(control_ids):
        L.append("  - " + y_str(cid))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    src = sys.argv[1]      # .../Y26M05-srg
    out = sys.argv[2]      # output dir
    inspec_root = os.path.join(src, "inspec")
    role_root = os.path.join(src, "ansible", "vmware-cloud-foundation-stig-ansible-hardening")

    recs = parse_all(inspec_root)
    varmap = load_var_map(role_root)
    # Sensible defaults for common Ansible runtime facts so on-appliance API calls target localhost.
    for k, v in {"ansible_host": "localhost", "inventory_hostname": "localhost",
                 "ansible_fqdn": "localhost"}.items():
        varmap.setdefault(k, v)
    rem = index_remediation(role_root)

    custom_root = os.path.join(out, "salt", "locke", "custom", "vcf9")
    bench_root = os.path.join(out, "benchmarks")
    os.makedirs(custom_root, exist_ok=True)
    os.makedirs(bench_root, exist_ok=True)

    tier_counts = Counter()
    bench_members = defaultdict(list)
    bench_display = {}
    rows = []  # for coverage report

    for cid in sorted(recs):
        rec = recs[cid]
        slug, display, osfinger = bench_for(rec)
        bench_display[slug] = display
        cdir = os.path.join(custom_root, comp_dir(rec))
        os.makedirs(cdir, exist_ok=True)

        actions = rem.get(cid, [])
        sls_text, tier = build_sls(rec, actions, varmap)

        with open(os.path.join(cdir, cid + ".sls"), "w", encoding="utf-8") as fh:
            fh.write(sls_text)
        write_check_meta(os.path.join(cdir, cid + ".meta"), rec, slug, osfinger)

        tier_counts[tier] += 1
        bench_members[slug].append(cid)
        rows.append((cid, slug, tier, "yes" if actions else "no", rec["severity"]))

    # benchmark meta files
    for slug, members in bench_members.items():
        write_benchmark_meta(
            os.path.join(bench_root, slug + ".meta"),
            slug, bench_display[slug],
            "Custom benchmark ported from the VMware Cloud Foundation 9.x STIG Readiness Guide.",
            members)

    write_support_files(out, recs, tier_counts, bench_members, bench_display, rows)

    print("controls:", len(recs))
    print("benchmarks:", len(bench_members))
    print("tiers:", dict(tier_counts))


def write_support_files(out, recs, tier_counts, bench_members, bench_display, rows):
    # sample_tests
    st = os.path.join(out, "sample_tests")
    os.makedirs(st, exist_ok=True)
    with open(os.path.join(st, "run_local_test.sh"), "w") as fh:
        fh.write(
            "#!/usr/bin/env bash\n"
            "# Assess (test=True) or remediate a single ported check with a local masterless minion.\n"
            "# Usage: ./run_local_test.sh <check_ref> [assess|remediate]\n"
            "#   e.g. ./run_local_test.sh locke.custom.vcf9.photon_5.PHTN-50-000007 assess\n"
            'CHECK="$1"; MODE="${2:-assess}"\n'
            'if [ "$MODE" = "remediate" ]; then TEST=""; else TEST="test=True"; fi\n'
            'salt-call --local --file-root=./salt state.apply "$CHECK" $TEST\n')
    os.chmod(os.path.join(st, "run_local_test.sh"), 0o755)

    # COVERAGE.md
    cov = [
        "# VCF 9.x (Y26M05) -> SaltStack SecOps: Coverage Report", "",
        "Total checks generated: **{0}**".format(len(recs)),
        "Total benchmarks: **{0}**".format(len(bench_members)), "",
        "## Remediation tier breakdown", "",
        "| Tier | Meaning | Count |", "|---|---|---|",
    ]
    tier_help = {
        "ansible-native": "Translated from Ansible remediation into idempotent native Salt states (file/sysctl/service/pkg/pam). Audit-correct under test=True.",
        "ansible-native-unguarded": "Real Ansible remediation that is a one-shot cmd.run with no derivable on-host audit; test=True over-reports until a guard/attestation is added.",
        "inspec-guarded": "Self-contained cmd.run with an InSpec-derived audit guard and a STIG-derived fix command.",
        "inspec-audit-only": "Audit derived from InSpec; no safe automated fix - reports compliant/non-compliant only.",
        "powercli-proxy": "API control (ESX/VM/vCenter/NSX). PowerCLI audit+fix extracted, gated behind pillar vcf_secops:enable_powercli; needs a PowerCLI proxy minion.",
        "manual-by-design": "Source InSpec control is itself manual/Not-Applicable; surfaced as a manual-review marker (faithful to source).",
        "manual": "No automatable audit/fix derivable from source; surfaced as a manual-review marker.",
    }
    for t, c in tier_counts.most_common():
        cov.append("| `{0}` | {1} | {2} |".format(t, tier_help.get(t, ""), c))
    cov += ["", "## Benchmarks", "", "| Benchmark | Display name | Checks |", "|---|---|---|"]
    for slug in sorted(bench_members):
        cov.append("| `{0}` | {1} | {2} |".format(slug, bench_display[slug], len(bench_members[slug])))
    cov += ["", "## Per-check detail", "",
            "| Control | Benchmark | Tier | Ansible remediation | Severity |", "|---|---|---|---|---|"]
    for cid, slug, tier, hasrem, sev in sorted(rows):
        cov.append("| {0} | {1} | {2} | {3} | {4} |".format(cid, slug, tier, hasrem, sev))
    with open(os.path.join(out, "COVERAGE.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(cov) + "\n")


if __name__ == "__main__":
    main()
