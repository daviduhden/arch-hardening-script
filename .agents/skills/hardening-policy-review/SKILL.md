---
name: hardening-policy-review
description: Review or change an Arch/Artix hardening measure, including its threat model, trade-offs, prompts, documentation, and rollback.
---

# Hardening Policy Review

Use this skill when adding, removing, or reviewing a measure in
`hardening.bash`, or when checking whether `README.md` still describes
the code accurately.

## Activation Conditions

- A sysctl, kernel parameter, module blacklist, package, service, or
  account policy is being added or changed.
- A README claim about security value, defaults, or compatibility is
  being edited.
- A reviewer asks whether a measure is still appropriate for current
  Arch/Artix kernels or init systems.

## Procedure

1. Locate the feature function in `hardening.bash` and read its
   detection, prompt, package, file, service, and rollback paths.
2. State the layer and threat: kernel self-protection, MAC, application
   isolation, network, local permissions, hardware attack surface, or
   privacy. Do not present a privacy measure as a security control.
3. Separate standard from strict/optional behavior. Identify the exact
   defaults and the trade-offs the prompt discloses.
4. Verify that the measure is opt-in, explains its impact before asking,
   and defaults to "no" where the impact is serious.
5. Check idempotency: writes go through `write_file` or
   `append_line_if_missing`; existing administrator files are backed up
   once; services are only changed when needed.
6. Check reversibility: every persistent change has a journal entry
   (`C`, `M`, `S+`, `S-`, `G`, `X`) or is explicitly documented as not
   reverted. Runtime-only changes must say so.
7. Check that enabling the measure does not silently depend on a
   third-party repository. Chaotic-AUR and AUR paths must be labeled and
   must not be required when the package is already installed.
8. Update `README.md` in the same change. Keep the feature table, caveat
   list, verification steps, and "Backups and Rollback" section
   consistent with the code.
9. Do not add a claim that was not verified against the kernel, Arch
   package defaults, or the code path. Prefer "reduces exposure" over
   "secures".

## Validation

- Inspect the exact function and README section together; do not rely on
  the feature table alone.
- Run only static checks:
  `bash -n hardening.bash`, `bash -n spoof-mac-addresses.bash`,
  `shellcheck hardening.bash`, and
  `shellcheck spoof-mac-addresses.bash`.
- Use `git diff --check` and `git status --short`.
- Confirm that no new runtime command was executed while reviewing.
- If a behavior change affects users, bump `VERSION` in
  `hardening.bash` and mention it in the change summary.

## Common Issues

- README claims a warning or feature that the code does not implement.
- A "removed" measure is still present in the feature table.
- A strict option is described without its real breakage (perf, ptrace,
  kexec, SMT, unsigned modules, old binaries).
- A sysctl is assumed to be applied by every init system without a
  service check.
- Package installation is described as harmless even though it expands
  the trust boundary or can create a partial upgrade.
- `--undo` is described as complete when runtime state, packages, or
  deliberate exceptions remain.
- The measure is called "idempotent" when it regenerates policy or runs
  an upgrade on every run.

## References

- `README.md`: Overview, Security Model, Features, Compatibility Notes,
  Backups and Rollback, Verification.
- `hardening.bash`: `feature_*`, `write_sysctl_file`,
  `apply_kernel_params`, `do_undo`.
- Linux kernel sysctl and parameter documentation:
  <https://docs.kernel.org/admin-guide/sysctl/> and
  <https://docs.kernel.org/admin-guide/kernel-parameters.html>.
- Arch Wiki: Security, AppArmor, Nftables, Microcode.
- Arch kernel configuration:
  <https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/blob/main/config.x86_64>.
