# SaltStack SecOps Port

This workspace captures the first-pass plan for porting the DoD compliance content in this repository to the Broadcom SaltStack Config SecOps custom content SDK.

Broadcom's current SDK page for `vRealize Automation SaltStack Config SecOps` lists `v8.4.0` as latest and identifies the custom-content tool as `secops_sdk`. Running `secops_sdk init` creates the target content layout:

- `benchmarks/` for benchmark `.meta` files
- `salt/locke/custom/` for custom check state `.sls` files and check `.meta` files
- `sample_tests/` for Docker-based state tests

The SDK downloads are login-gated, so this repo does not currently contain a generated SDK scaffold or verified `.meta` schema. Treat this directory as the conversion workspace until the actual SDK output is available.

## Source Content Shape

The source repo is a product/version content library:

- STIG and SRG guidance metadata is indexed in `saf-manifest.json`.
- Audit automation is primarily Chef InSpec profiles under product/version `inspec/` paths.
- Remediation automation is primarily Ansible roles/playbooks under product/version `ansible/` paths.
- Some products also contain PowerCLI, TAS release assets, Kubernetes policies, reports, and CKL files.

The easy SecOps candidates are OS and appliance controls where the check can run on a Salt minion:

- Photon OS controls, especially `photon/5.0/v3r3-srg`
- Ubuntu controls under `ubuntu/`
- Appliance-local file, service, package, sysctl, PAM, SSH, auditd, rsyslog, and permissions checks

The harder candidates need a wrapper or a different execution model:

- vSphere, NSX, Aria, VCF, and AVI API checks that currently use InSpec custom resources or product APIs
- Controls that expect PowerCLI, kubectl, vracli, or appliance-specific local commands
- Multi-target controls where one benchmark item maps to several Salt targets

## Conversion Model

The practical mapping is:

| Source repo artifact | SecOps artifact |
| --- | --- |
| `saf-manifest.json` guidance item | Benchmark `.meta` seed |
| InSpec profile `inspec.yml` | Benchmark title, version, inputs, supported platform notes |
| InSpec `controls/*.rb` metadata | Check `.meta` seed |
| InSpec `describe` logic | Salt check state `.sls` implementation |
| InSpec `desc 'fix'` and Ansible tasks | Remediation state or manual remediation text |
| InSpec tags `severity`, `gid`, `rid`, `stig_id`, `cci`, `nist`, `gtitle`, `satisfies` | Check metadata fields |
| Ansible `defaults/main.yml` control booleans | Enable/disable flags for generated checks/remediations |

Do not bulk-convert everything in one pass. Build one benchmark family, validate in SecOps, then widen.

## Recommended Pilot

Start with `photon/5.0/v3r3-srg`.

Why:

- It is a current OS-target baseline.
- Most controls map naturally to Salt primitives such as `file.*`, `service.*`, `pkg.*`, `cmd.run`, `sysctl.*`, and `ini.options_present`.
- The matching Ansible role already encodes safe remediation sequencing, backups, handler restarts, and control-level enable flags.
- It avoids product API authentication and topology problems while the SDK schema is being proven.

Pilot acceptance criteria:

- One generated SecOps benchmark imports without SDK validation errors.
- A small group of Photon controls reports pass/fail against a test minion.
- One low-risk remediation applies idempotently in a test VM.
- Metadata keeps STIG/SRG IDs, CCIs, NIST references, severity, check text, fix text, and source path.

## Workflow

1. Run the inventory extractor to create a control map:

   ```sh
   ruby saltstack-secops/tools/inspec_control_inventory.rb photon/5.0/v3r3-srg --format csv > /tmp/photon-5-v3r3-controls.csv
   ```

2. Install or copy the Broadcom `secops_sdk` binary into a scratch directory and run:

   ```sh
   chmod 755 ./secops_sdk
   ./secops_sdk init
   ```

3. Compare the generated sample `.meta` files to the inventory fields and lock the schema mapping.

4. Generate a small hand-reviewed benchmark:

   - `benchmarks/vmware-photon-5.0-v3r3-srg.meta`
   - `salt/locke/custom/phtn_50_000003.meta`
   - `salt/locke/custom/phtn_50_000003.sls`

5. Validate with `secops_sdk` and the generated `sample_tests/`.

6. Add a real generator only after the SDK schema is confirmed.

## Initial Porting Rules

- Preserve control IDs exactly in metadata; use Salt-safe filenames for state IDs.
- Preserve original check/fix text for assessor traceability.
- Keep source paths in generated metadata so a SecOps finding can be traced back to this repo.
- Prefer direct Salt state modules for OS controls.
- Use `cmd.run` checks only when a native Salt module is not expressive enough.
- Keep remediation separate from detection until the benchmark import and reporting path is proven.
- Gate disruptive remediations behind explicit variables, matching the Ansible defaults pattern.

## Inventory Helper

`tools/inspec_control_inventory.rb` extracts control metadata from InSpec profiles. It is intentionally schema-neutral: it does not generate `.meta` files until the real SDK schema is present.

In a repo-wide smoke test, it parsed 9,593 control records. The remaining `controls/*.rb` files are InSpec wrapper files that call `include_controls` rather than defining their own `control` blocks.

Examples:

```sh
ruby saltstack-secops/tools/inspec_control_inventory.rb --format jsonl --limit 5
ruby saltstack-secops/tools/inspec_control_inventory.rb photon/5.0/v3r3-srg --format csv
ruby saltstack-secops/tools/inspec_control_inventory.rb aria/automation/8.x/v1r6-srg --format json --include-text
```
