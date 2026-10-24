---
name: firewall-and-boot-safety
description: Analyze and safely change nftables, SSH, sysctl, kernel parameters, bootloader entries, and other lockout-capable behavior.
---

# Firewall and Boot Safety

Use this skill before changing anything that can sever remote access,
break forwarding, prevent boot, or silently weaken a security control.

## Activation Conditions

- Editing `/etc/nftables.conf`, the generated `nftables_ruleset`, or
  firewall service handling.
- Editing SSH configuration, the `PermitRootLogin` drop-in, PAM, or
  root-account restrictions.
- Editing sysctl values, kernel parameters, `lsm=`, module blacklists,
  GRUB, systemd-boot, Syslinux, or bootloader regeneration.
- Editing `rfkill`, hostname/DHCP, DNS-related package behavior, or
  service start/stop logic.

## Procedure

### Required Impact Analysis

Before editing, write down:

1. What traffic, login path, or boot path can be lost.
2. Whether the change applies immediately, at next service restart, or
   after reboot.
3. How to recover locally (console, second admin account, live media,
   backup file).
4. Which init systems and bootloaders are affected.
5. What `--undo` restores and what it deliberately leaves alone.

If the answer is "the only recovery is a reboot" or "the only admin is
remote", stop and require an explicit user decision.

### Firewall Procedure

1. Read `feature_firewall`, `nftables_ruleset`, and `sshd_running`.
2. Keep the default-deny inbound policy, established/related accept,
   loopback accept, and required ICMP/ICMPv6.
3. Do not reintroduce `flush ruleset`. The generated file removes only
   the project table with `destroy table inet arch_hardening`, leaving
   Docker/libvirt/podman and administrator tables in place.
4. Remember that the project's default-drop `forward` chain still
   breaks container/VM forwarding. Document this.
5. Detect SSH whether it is running or enabled. Allow inbound SSH
   only when the user confirms. When confirmed, allow every numeric
   `Port` found in `sshd_config`/`sshd_config.d`, defaulting to 22;
   reject non-numeric values.
6. Validate the generated file with `nft -c -f` before writing. In
   `--dry-run`, validation may be skipped when `nft` is not installed;
   do not claim it ran.
7. If nftables is already active, state that the new file takes effect
   on restart/reboot; `start` does not reload an active service.
8. Do not reload or flush a live ruleset as part of a documentation
   task.

### SSH and Account Procedure

1. Back up and edit only the project drop-in under
   `/etc/ssh/sshd_config.d/`.
2. Check that `sshd_config` includes `sshd_config.d/*.conf`; warn if it
   does not.
3. Run `sshd -t`; on failure, keep the previous configuration and
   report the drop-in path.
4. When available, check the effective value with `sshd -T`; an earlier
   drop-in can override the project file.
5. For `pam_wheel`, do not claim success when `pam_rootok.so` is absent
   and no insertion happened. Warn if the wheel group has no members.
6. `passwd -l root` is immediate and is not undone by `--undo`. The
   locked password cannot be used at the console; recovery requires
   sudo or another administrative account.

### Boot and Kernel Procedure

1. Back up `/etc/default/grub` before editing and `/boot/grub/grub.cfg`
   before regeneration. Restore both if `grub-mkconfig` fails.
2. Keep the managed block markers and replace the block idempotently.
   Do not write to `/etc/default/grub.d/`; GRUB does not read it.
3. For systemd-boot, edit only kernel entries with a `linux` line and
   `vmlinuz`; support the three common entry directories. Do not claim
   that `bootctl update` creates a linux-hardened entry.
4. For Syslinux, edit only the Arch/Artix label and its `APPEND` lines.
5. Scan `lsm=` only from the active boot configuration plus
   `/proc/cmdline` and `/etc/kernel/cmdline`. A stale file for another
   bootloader must not suppress or contradict the change. Never
   overwrite an administrator `lsm=` that lacks AppArmor; warn instead.
6. Sysctl files are written but not applied immediately. Say "after
   reboot" or show `sysctl --system`; do not claim live enforcement.
7. Module blacklists generated from the running kernel require a
   reboot and may not cover an initramfs that loads the module early.
8. `rfkill block all` is immediate and can drop the connection carrying
   the session; systemd may persist the block.

## Validation

- Static inspection of the generated heredoc, sed/awk expressions, and
  backup paths.
- `bash -n hardening.bash`, `shellcheck hardening.bash`,
  `git diff --check`, `git status --short`.
- Confirm no live `nft`, `systemctl`, `sshd`, `sysctl`, `grub-mkconfig`,
  `rfkill`, or `passwd` command was run.
- Check README claims against the exact code path, including
  "validated", "immediate", and "reverted" wording.

## Common Issues

- `flush ruleset` deleting unrelated firewall rules.
- Allowing only port 22 while SSH listens elsewhere, or allowing a
  non-numeric `Port` value without validation.
- Enabling USBGuard without a usable policy and blocking the keyboard.
- `module.sig_enforce=1` or a broken initramfs making the system
  unbootable.
- `oops=panic` causing reboot loops.
- `ipv6.disable=1` on an IPv6-only network.
- Reading a stale GRUB drop-in or another bootloader's entries when
  deciding whether `lsm=` is present.
- Treating `--undo` as a live firewall/service rollback.
- Treating `nft -c` or `sshd -t` as proof that the running system uses
  the new configuration.

## References

- `hardening.bash`: `feature_firewall`, `nftables_ruleset`,
  `sshd_running`, `feature_root_restrictions`,
  `existing_lsm_configuration`, `apply_*_params`, `do_undo`.
- `README.md`: nftables, AppArmor, boot parameters, root restrictions,
  Backups and Rollback, Verification.
- nftables wiki: <https://wiki.nftables.org/>.
- OpenSSH `sshd_config(5)` and `sshd(8)`.
- Arch Wiki: Nftables, OpenSSH, AppArmor, GRUB, systemd-boot.
