# Porting Guide: VCF 9.x STIG (InSpec + Ansible) → SaltStack SecOps

This document explains how the source automation was converted to SaltStack SecOps custom
content, what the converter does, the fidelity of each output, and how to extend or correct it.

## 1. Source vs. target models

The source content has two halves per STIG control:

* **InSpec** (`inspec/.../controls/<ID>.rb`) — the *audit*. Also the authoritative source of
  STIG metadata: title, discussion, check text, fix text, severity, impact, CCI, NIST,
  SRG/`gtitle`, and `stig_id`.
* **Ansible** (`ansible/.../roles/<role>/tasks/*.yml`) — the *remediation*, with each task or
  block tagged with the control ID (e.g. `tags: [PHTN-50-000007]`).

SaltStack SecOps has a single artifact per control:

* A **state** (`.sls`) that is the audit *and* the remediation — assessed with `test=True`
  (a predicted change ⇒ non-compliant) and enforced when applied.
* A **meta** (`.meta`, YAML) describing the check and tying it to one or more **benchmarks**.

So the port merges the InSpec metadata + audit and the Ansible remediation into one Salt state
plus its metadata file. Benchmarks are created per VCF component.

## 2. What the converter does (`tools/`)

| File | Responsibility |
|---|---|
| `inspec_parser.py` | Parses every `controls/*.rb`, extracts metadata + audit body, de-duplicates by control ID (the same ID is reused across composite baselines), records each control's canonical component. |
| `ansible_parser.py` | Indexes remediation tasks by control ID (via tags / name prefix), descends into `block:`, captures the actionable module + args, and resolves `{{ vars }}` from `defaults/`, `vars/`, and `group_vars/`. |
| `emit.py` | Translates an Ansible action into native Salt states, derives audit guards from InSpec, extracts PowerCLI, and renders the `.sls`. |
| `convert.py` | Orchestrates: component→benchmark taxonomy, writes `.sls` + `.meta` per check, benchmark metas, `COVERAGE.md`, and sample tests. |

Run it against any similarly-structured release:

```bash
python3 tools/convert.py /path/to/<release>-srg /path/to/output
```

## 3. Remediation tiers

Every check is labeled with a `# Tier:` comment in its `.sls` header. The tier reflects how
the audit/remediation was derived and how much it can be trusted to assess accurately.

| Tier | Count | How it was produced | Audit accuracy under `test=True` |
|---|---|---|---|
| `ansible-native` | 279 | Ansible module → idempotent native Salt state (`file.replace`, `sysctl.present`, `service.running`, `pkg.installed`, `file.managed`, …). | **Accurate** — native states are idempotent, so a predicted change correctly means non-compliant. |
| `ansible-native-unguarded` | 41 | Ansible remediation that is a one-shot `cmd.run` (e.g. `aide --init`, vendor scripts, REST `PUT`/`POST`) with no derivable on-host check. | **Over-reports** — an unguarded `cmd.run` always shows a pending change. Add an `unless`/`onlyif` or an attestation. Flagged in the header. |
| `powercli-proxy` | 65 | API control (ESX/VM/vCenter/NSX). The `Get-`/`Set-`/`esxcli` commands are extracted from the InSpec `powercli_command`/check/fix text into a `pwsh` state, gated behind pillar `vcf_secops:enable_powercli`. | Accurate *when enabled on a PowerCLI proxy with a value-comparison guard*; otherwise resolves to a manual marker. |
| `inspec-audit-only` | 46 | A shell audit guard was derived from the InSpec resource, but no safe automated fix exists. Reports compliant/non-compliant; remediation is a documented no-op. | **Accurate audit**, no automated fix. |
| `manual-by-design` | 34 | The source InSpec control is itself manual / Not-Applicable ("must be reviewed manually", "is N/A", "not deployed"). | Surfaced as a manual-review marker — faithful to the source. |
| `manual` | 47 | No automatable audit or fix could be derived (InSpec uses `parse_config_file`/`json`/`postgres_session`/custom matchers and there is no Ansible task). | Manual-review marker. Candidate for hand-authoring. |

## 4. Ansible module → Salt state mapping

| Ansible module | Salt state | Notes |
|---|---|---|
| `lineinfile` (present) | `file.replace` + `append_if_not_found` | Uses the task `regexp` as the pattern. Falls back to `file.append` when there is no regexp. |
| `lineinfile` (absent) | `file.replace` → `''` | Removes the matched line. |
| `replace` | `file.replace` | |
| `blockinfile` | `file.blockreplace` | |
| `ansible.posix.sysctl` | `sysctl.present` | Preserves the target `sysctl_file` as `config`. |
| `systemd` / `service` | `service.running` / `service.dead` | Maps `enabled` → `enable`. |
| `community.general.pam_limits` | `file.replace` on `limits.conf` | Pattern keyed on domain/type/item. |
| `community.general.pamd` | `file.replace` on `/etc/pam.d/<svc>` | Best-effort: ensures the module argument is present. Verify complex PAM stacks by hand. |
| `copy` / `template` | `file.managed` | Source content is not portable from the role; emitted with `source: salt://vcf9/files/<ID>` and enforced mode/owner/group. Provide the file or convert to inline `contents`. |
| `file` | `file.directory` / `file.absent` / `file.managed` | By `state`. |
| `apt`, and `tdnf/dnf/yum` invoked via shell | `pkg.installed` / `pkg.removed` | Package-manager shell commands are recognized and converted to idempotent pkg states. |
| `command` / `shell` (changing) | `cmd.run` (+ `unless` when derivable) | Read-only steps (`changed_when: false`, `SHOW`/`SELECT`/`rpm -q`/`sysctl <name>` …) are dropped — they are checks, not fixes. `ALTER SYSTEM SET` gets a synthesized `SHOW` guard. |
| `uri` (POST/PUT/DELETE) | `cmd.run` with `curl` | Appliance REST remediation; `GET` is dropped as read-only. Body templates appear as placeholders (see §6). |
| `community.general.timezone` | `timezone.system` | |

## 5. Audit-guard derivation (for `cmd.run`)

Because native states are self-assessing but `cmd.run` is not, the converter derives an
`unless` guard from the InSpec audit where possible:

* `kernel_parameter('k'){ value eq N }` → `[ "$(sysctl -n k)" = "N" ]`
* `file('p'){ content match /RE/ }` → `grep -Pqz 'RE' p`
* `file('p'){ should exist }` → `test -e p`
* `command('c'){ stdout match /RE/ }` → `c | grep -Pq 'RE'`
* `command('c'){ exit_status eq 0 }` → `c`
* PostgreSQL `ALTER SYSTEM SET x = 'v'` → `... SHOW x ... | grep -qi 'v'`
* PowerCLI: `Get-…` wrapped with a `-eq <value>` comparison taken from the `Set-… -Value`.

When no guard can be derived, the step is left unguarded and the file header carries a WARNING.

## 6. Known limitations — review these

1. **API controls need a proxy minion.** ESX/VM/vCenter/NSX checks (`powercli-proxy`) cannot
   run on an ordinary minion. Enable pillar `vcf_secops:enable_powercli: true` on a
   PowerCLI-capable proxy and supply connection details in pillar. The extracted `Set-`/`Get-`
   commands are a faithful starting point but should be reviewed per control.
2. **Runtime placeholders `<<…>>`.** A minority of checks (NSX/appliance REST and loop-based
   Ansible tasks) contain `<<item>>`, `<<item.path>>`, or `<<lookup('template', '….j2')>>`.
   These are Ansible loop variables and Jinja request-body templates that have no static value.
   Supply them via pillar or by porting the corresponding `.json.j2` body. Affected files are
   flagged with a header WARNING.
3. **`copy`/`template` file bodies** are not carried over. Provide the referenced file under
   `salt://vcf9/files/<ID>` or convert to inline `file.managed` `contents`.
4. **PAM (`pamd`) translations are best-effort.** Validate `/etc/pam.d` changes on a test host.
5. **`osfinger`** is set to `VMware Photon OS-5` for Photon and Photon-based appliances, and
   empty (`[]`) for API/proxy controls. Adjust to match the grains your minions actually report.
6. **`refs` schema.** The cross-reference block (DISA STIG / SRG / CCI / NIST) is valid YAML and
   informative, but if your SDK version enforces a specific `refs` schema, align it with the
   `sample_tests` meta shipped in your SDK build.

## 7. Recommended workflow to production

1. Start with the `ansible-native` tier for a component (e.g. `photon_5`) — highest fidelity.
2. Stand up a CentOS/Photon test minion, run each check `test=True`, then remediate, then
   `test=True` again to confirm it reports compliant (idempotency check).
3. For `ansible-native-unguarded` and `inspec-audit-only`, add `unless`/`onlyif` guards or
   SecOps attestations so assessment is accurate.
4. For `powercli-proxy`, configure a proxy minion and validate the extracted commands per
   control against a lab vCenter/NSX.
5. Hand-author the `manual` tier checks where automation is feasible.
6. Build (`secops_sdk build -a`) and import; create policies from the `vcf9_*` benchmarks.
