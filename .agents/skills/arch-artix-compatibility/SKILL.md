---
name: arch-artix-compatibility
description: Safely change Arch/Artix detection, init-system services, bootloaders, network managers, and package names without breaking supported combinations.
---

# Arch/Artix Compatibility

Use this skill when touching system detection, service management,
bootloader handling, network-manager handling, or distribution-specific
package names.

## Activation Conditions

- Editing `detect_distro`, `detect_init`, `detect_bootloader`,
  `detect_network_manager`, `detect_cpu_vendor`, `init_service_pkg`, or
  `service_name_for`.
- Adding a service, package, bootloader path, or network-manager branch.
- A change is claimed to work on systemd, OpenRC, runit, s6, and dinit,
  or on GRUB, systemd-boot, and Syslinux.

## Supported Matrix

| Axis | Values |
|---|---|
| Distribution | Arch (`ID=arch`), Artix (`ID=artix`) |
| Init | systemd, OpenRC, runit, s6, dinit |
| Bootloader | GRUB, systemd-boot, Syslinux, none |
| Network | NetworkManager, systemd-networkd, iwd, none (macchanger) |
| Architecture | x86_64; only some ASLR sysctls are gated on it |

Distribution detection accepts only `ID=arch` or `ID=artix`.
`--disable-checks` bypasses the distribution check but not init
detection, root checks, or package assumptions.

## Procedure

1. Read the detection function and list every accepted value and
   fallback. Do not infer support from the README alone.
2. For a new service, add both the service name mapping and the Artix
   package name. `init_service_pkg` uses `<pkg>-<init>`; check the
   s6/runit/dinit exceptions in `service_name_for`.
3. For a bootloader edit, verify the file path, backup, idempotency,
   regeneration command, and failure behavior for GRUB, systemd-boot,
   and Syslinux. GRUB reads `/etc/default/grub`, not
   `/etc/default/grub.d/`.
4. For systemd-boot, search `/boot/loader/entries`,
   `/efi/loader/entries`, and `/boot/efi/loader/entries`; skip
   non-vmlinuz entries. Do not assume `bootctl update` creates a kernel
   entry.
5. For Syslinux, edit only `MENU LABEL Arch Linux` or
   `MENU LABEL Artix Linux` and only its `APPEND` lines. Artix labels
   must not be ignored.
6. For network configuration, confirm whether the manager is
   NetworkManager, systemd-networkd, or iwd. Do not write a catch-all
   systemd-networkd `.network` file; use drop-ins.
7. For Artix, confirm that a package exists for the active init before
   requiring it. If availability is uncertain, warn rather than invent a
   service definition.
8. Update README compatibility notes and the supported-systems table
   when the matrix changes.

## Validation

- Static inspection only: trace every `case "$init_system"` and
  `case "$bootloader"` branch for missing fallbacks.
- `bash -n hardening.bash` and `shellcheck hardening.bash`.
- `git diff --check`; check that no generated service or bootloader file
  is written during review.
- Verify that `service_name_for` and `init_service_pkg` are used at each
  call site instead of hardcoded unit names.

## Common Issues

- Assuming every Artix s6 service is named `<pkg>-srv`; only Tor and
  chrony have exceptions in the current code.
- Assuming chrony is always `chrony`; dinit uses `chronyd`.
- Forgetting that runit enables services by symlink and may start them
  immediately.
- Treating a non-systemd mask as real; only systemd has `mask`.
- Editing `/etc/default/grub.d/` for GRUB, which GRUB does not read.
- Forgetting the warning for systemd-boot without systemd.
- Writing a systemd-networkd drop-in for only `/etc/systemd/network` and
  missing `/usr/lib/systemd/network`.
- Assuming `/etc/sysctl.d/` is applied on every init; the script writes
  the file but does not install a sysctl service.
- Assuming package names or service names from one Artix init apply to
  another.

## References

- `hardening.bash`: `detect_*`, `svc_*`, `init_service_pkg`,
  `service_name_for`, `apply_*_params`.
- `README.md`: Supported Systems, Compatibility Notes.
- Arch Wiki: systemd-boot, GRUB, Syslinux, NetworkManager,
  systemd-networkd, OpenRC.
- Artix package database: <https://packages.artixlinux.org/>.

## Maintenance & Continuous Learning

Whenever this skill is used to change the repository, review this skill after
the implementation. Correct procedures that proved wrong, update commands,
paths, configuration and examples, incorporate reusable findings, and remove
outdated assumptions. Review the applicable root and nested `AGENTS.md` files,
specialized agents and related skills; update only the knowledge affected by
the work. Validate local references and run
`python3 scripts/validate-agent-knowledge.py --scope worktree` plus the
applicable project checks. For pull request comparisons, use the documented
`--scope range --base BASE_REF --head HEAD_REF` command. The canonical validator
is read-only and is required even when a task restricts execution of project
scripts; this does not authorize running installers or changing the host.
Report checks actually performed. A structural pass does not prove semantic
relevance, and a task is incomplete until synchronization is validated.
