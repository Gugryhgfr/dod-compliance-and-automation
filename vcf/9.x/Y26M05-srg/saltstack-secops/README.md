# VMware Cloud Foundation 9.x STIG — SaltStack SecOps Compliance Content

This directory is a port of the VCF 9.x (Y26M05) STIG Readiness Guide automation to
**SaltStack SecOps Compliance** custom content. It is generated from the InSpec audit
baselines and the Ansible remediation roles that ship in this release, and is laid out to
match the output of the SecOps Custom Content SDK (`secops_sdk init`).

```
saltstack-secops/
├── benchmarks/                     # 20 custom benchmark .meta files (one per VCF component)
├── salt/
│   └── locke/
│       └── custom/
│           └── vcf9/
│               ├── photon_5/       # <CONTROL-ID>.sls (Salt state) + <CONTROL-ID>.meta (metadata)
│               ├── vsphere_esx/
│               ├── vsphere_vcenter/
│               ├── nsx_manager/
│               └── ...             # 20 component folders, 512 checks total
├── sample_tests/                   # helper to assess/remediate a single check locally
├── tools/                          # the converter (re-runnable for other releases)
├── COVERAGE.md                     # generated per-check coverage + tier report
├── PORTING-GUIDE.md                # how the mapping works, limitations, how to extend
└── README.md
```

## How SecOps content maps to the source

A SaltStack SecOps **check** is a Salt state file (`.sls`) plus a metadata file (`.meta`).
The audit and remediation are the *same* state, run two ways:

| SecOps action | Salt invocation | Result |
|---|---|---|
| **Assess** | `state.apply ... test=True` | A predicted change ⇒ host is **non-compliant** |
| **Remediate** | `state.apply ...` | The state is enforced |

This unifies the two halves of the source content: the **InSpec** baseline supplies the
metadata and audit logic; the **Ansible** roles supply the remediation. Both collapse into a
single Salt state per control.

```
InSpec control (audit + STIG metadata) ─┐
                                         ├─►  <CONTROL-ID>.sls  (audit via test=True / remediate via apply)
Ansible task(s) for that control (fix) ─┘     <CONTROL-ID>.meta (display name, description, refs, benchmark)
```

## Content summary

* **512** checks across **20** benchmarks (one benchmark per VCF component).
* **385** checks carry real remediation (279 native Salt states + 41 guarded/command + 65 PowerCLI/API).
* **46** are audit-only (assessment derived from InSpec; no safe automated fix).
* **34** are manual/Not-Applicable in the source STIG itself and are surfaced as such.
* **47** had no automatable audit or fix in the source and are flagged for manual review.

See `COVERAGE.md` for the full per-check breakdown and `PORTING-GUIDE.md` for methodology.

## Using the content

### 1. Initialize a real SDK working directory
Download the SecOps Custom Content SDK from the Broadcom developer portal and initialize it:

```bash
chmod 755 secops_sdk
./secops_sdk init
```

### 2. Drop this content in
Copy the generated content into the initialized SDK tree:

```bash
cp -r benchmarks/*            <sdk>/benchmarks/
cp -r salt/locke/custom/vcf9  <sdk>/salt/locke/custom/
```

### 3. Test a check locally (Docker, per the SDK)
Each check is an ordinary Salt state, referenced by its path under `salt/`:

```bash
# Assess only (test=True) — a predicted change means non-compliant
./ salt-call --local state.apply locke.custom.vcf9.photon_5.PHTN-50-000007 test=True

# Remediate
./ salt-call --local state.apply locke.custom.vcf9.photon_5.PHTN-50-000007
```

`sample_tests/run_local_test.sh <check_ref> [assess|remediate]` wraps this.

### 4. Build and import
```bash
./secops_sdk build -a
```
This produces `_dist/secops_custom.tar.gz` (and a timestamped copy). Import it under
**Administration → SecOps → Compliance Content** in SaltStack Config, then build policies
that include the `vcf9_*` benchmarks.

## Important notes

* **OS / appliance controls** (Photon OS, and the Photon-based appliance services: NGINX,
  Apache httpd, PostgreSQL, Lighttpd/VAMI, Envoy) map directly to native Salt states and run
  on an ordinary minion installed on the appliance.
* **API-managed controls** (vSphere ESX/VM, vCenter advanced settings, NSX Manager/routing)
  cannot be enforced by an on-host minion. They are emitted as PowerCLI/REST states gated
  behind the pillar flag `vcf_secops:enable_powercli` and require a **PowerCLI-capable proxy
  minion** with a connection to vCenter/NSX. Connection details are expected in pillar
  (`vcf_secops:`). Until enabled, these checks resolve to a manual-review marker.
* Always test in a representative non-production environment first. These states change live
  system configuration when applied.

## Regenerating

The converter under `tools/` is re-runnable against any VCF release that follows the same
InSpec + Ansible layout:

```bash
python3 tools/convert.py /path/to/<release>-srg /path/to/output
```
