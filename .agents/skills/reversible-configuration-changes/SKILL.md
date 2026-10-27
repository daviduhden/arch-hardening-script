---
name: reversible-configuration-changes
description: Add or review file, service, and state changes so they are idempotent, backed up once, journaled correctly, and reversible with --undo.
---

# Reversible Configuration Changes

Use this skill whenever a change writes a file, edits an administrator
file, enables or masks a service, sets a setuid bit, or changes the
undo journal.

## Activation Conditions

- Adding a `write_file`, `append_line_if_missing`, `backup_existing`,
  `journal_add`, or `svc_*` call.
- Changing `do_undo`, the journal format, backup naming, or `--dry-run`.
- Reviewing why a rerun is not idempotent or why `--undo` leaves state
  behind.

## State Model

- State directory: `/var/lib/arch-hardening-script`.
- Journal: `/var/lib/arch-hardening-script/journal`.
- Backups: `<path>.arch-hardening.bak`, created once and never
  overwritten.
- Journal entries are tab-separated:
  - `C<TAB>path` - file created by the script; undo removes it.
  - `M<TAB>path<TAB>backup` - existing file backed up; undo restores it.
  - `S+<TAB>service` - service enabled; undo disables it.
  - `S-<TAB>service<TAB>prev_enabled<TAB>prev_masked` - service masked;
    undo restores the prior mask state and enabled state.
  - `G` - GRUB configuration was regenerated; undo regenerates it.
  - `X<TAB>path` - setuid bit set; undo clears it.
  - `I<TAB>packages` - packages installed; undo intentionally ignores
    this entry.

## Procedure

1. Use `write_file` for whole-file content. It compares content,
   backs up an existing administrator file once, preserves its mode,
   and journals `C` or `M`.
2. Use `append_line_if_missing` for one-line additions. It checks the
   exact line, backs up once, and ensures a trailing newline before
   appending.
3. Use `backup_existing` before a targeted edit that cannot use the
   helpers. Record the matching `M` entry and restore it in `do_undo`.
4. Never record both `C` and `M` for the same path. A file created by
   the script must be removed on undo; a pre-existing file must be
   restored.
5. Do not journal while `IN_UNDO=1`. `journal_add` already guards this;
   keep it that way.
6. In `--dry-run`, log the planned change, increment `CHANGES` where
   appropriate, and do not touch the filesystem.
7. For services, use `svc_enable`, `svc_start`, `svc_disable`,
   `svc_mask`, and `svc_unmask`. Do not hardcode init-specific commands.
   Record the previous enabled and masked state before masking.
8. For `--undo`, handle every entry type you add, tolerate missing
   backups with a warning, and do not delete a path that was changed by
   another tool without explaining the limitation.
9. Document deliberate exceptions in README: installed packages,
   `passwd -l root`, `rfkill`, `timedatectl set-ntp 0`, live firewall
   rules, runtime sysctl values, and running services.

## Validation

- Static inspection: trace each write to either a `C`/`M` entry or a
  documented exception.
- Confirm `write_file` is called with a full path and deterministic
  content.
- Confirm a second identical run would log "Unchanged" or skip the
  service operation.
- Run `bash -n hardening.bash` and `shellcheck hardening.bash`.
- Use `git diff --check` and inspect the diff for accidental journal
  format changes.
- Do not execute a real run or `--undo` on the host to test.

## Common Issues

- Journaling `C` for an existing file, so undo deletes it instead of
  restoring it.
- Calling `journal_add` while replaying the journal and extending the
  file being read.
- Backing up on every run instead of once.
- Appending to a file without a final newline and concatenating lines.
- Editing `/etc/pam.d/*`, `/etc/pacman.conf`, or bootloader entries
  without a backup or journal entry.
- Masking a service that was already masked and then unmasking it on
  undo.
- Treating `svc_disable` as "stop"; on systemd it only disables.
- Assuming `--undo` reloads nftables, stops services, or reverses
  packages. It does not.
- Adding a test-only root prefix or environment override; all managed
  paths are absolute by design.

## References

- `hardening.bash`: `journal_add`, `journal_has`, `write_file`,
  `backup_existing`, `append_line_if_missing`, `svc_*`, `do_undo`.
- `README.md`: Backups and Rollback.
- Removed test scaffolding: commits `7ea62a6` and `6d86f6f`.

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
