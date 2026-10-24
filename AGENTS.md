# Agent Instructions

## Project

This repository contains an interactive hardening and privacy script
for Arch Linux and Artix Linux. The working tree is small:

- `hardening.bash` - main interactive orchestrator.
- `spoof-mac-addresses.bash` - standalone MAC spoofing payload used by
  the macchanger fallback service.
- `README.md` - user-facing behavior, trade-offs, and verification.
- `LICENSE` - GNU GPL v3.

Both scripts are GPL-3.0-or-later. Preserve their copyright and license
headers.

## Architecture

`hardening.bash` runs `main` in this order: parse arguments, load an
optional config file, handle `--undo`, detect the distribution, init
system, bootloader, network manager, and CPU vendor, then run the
interactive features. Kernel parameters are accumulated and applied to
the bootloader at the end.

Key internals:

- `write_file`, `append_line_if_missing`, and `backup_existing` perform
  idempotent file changes and create `.arch-hardening.bak` backups.
- `/var/lib/arch-hardening-script/journal` records created files (`C`),
  modified files (`M`), enabled services (`S+`), masked services (`S-`),
  GRUB regeneration (`G`), and the bubblewrap setuid bit (`X`).
- `--undo` replays the journal. It does not uninstall packages or
  reverse every runtime action; read the README section "Backups and
  Rollback" before changing undo behavior.
- `--dry-run` skips writes and command execution, but it still performs
  read-only probes. It is not a sandbox and its plan can be incomplete
  when a package or repository is absent.

Supported combinations are Arch/Artix, systemd/OpenRC/runit/s6/dinit,
GRUB/systemd-boot/Syslinux, and NetworkManager/systemd-networkd/iwd or
the macchanger fallback. Do not silently narrow this matrix.

## Conventions

- Use Bash with `set -euo pipefail`; keep absolute paths.
- Use the existing helpers instead of ad-hoc file writes or service
  commands.
- Keep ASCII output, tab indentation in scripts, and roughly 72-column
  lines. Do not add ANSI colors or emoji.
- Quote expansions. Avoid `eval`, unquoted globs, and new runtime
  dependencies unless the README and checks are updated.
- Bump `VERSION` for behavior changes and keep `--version`/README
  consistent.
- Keep commit subjects imperative and focused if a maintainer asks you
  to commit. This task does not authorize commits.
- Check `git status --short` before editing and preserve unrelated
  pre-existing work. Never revert or overwrite someone else's changes.

## Commands That Actually Exist

Static checks confirmed by the repository:

```sh
bash -n hardening.bash
bash -n spoof-mac-addresses.bash
shellcheck hardening.bash
shellcheck spoof-mac-addresses.bash
git diff --check
git status --short
```

There is no Makefile, CI configuration, test runner, or automated test
suite. Do not document or claim `make test`, a `tests/` directory, or a
mock suite as current. The mock suite was removed in commit `7ea62a6`
and the test-only alternate root was removed in `6d86f6f`.

Runtime commands such as `sudo bash hardening.bash`, `pacman`,
`systemctl`, `nft`, `sysctl`, `grub-mkconfig`, and `passwd` are
documented for users, not for agents working on this repository.

## Security and Testing Policy

- Never execute either script during documentation or review work,
  including `--dry-run` and `--help`. Do not run the hardening, package
  managers, service managers, firewall, bootloader, `passwd`, `rfkill`,
  or network-changing commands on the host.
- Do not install packages, modify the system, run destructive tests,
  commit, or push unless the user explicitly authorizes it.
- Before changing firewall, SSH, DNS, kernel, bootloader, sysctl, or
  service behavior, write an impact analysis: default-deny effects,
  lockout paths, rollback, and affected init/bootloader combinations.
- Prefer static inspection and the checks above. If a real test is ever
  required, use a disposable VM/container, never the live host.
- Do not reintroduce `ARCH_HARDENING_TEST_ROOT`, mock-log assertions, or
  a fake root without an explicit maintainer request.

## Skills

Load the relevant skill before editing:

- [hardening-policy-review](.agents/skills/hardening-policy-review/SKILL.md)
  - review a measure's threat model, trade-offs, prompts, and README.
- [arch-artix-compatibility](.agents/skills/arch-artix-compatibility/SKILL.md)
  - handle init systems, bootloaders, network managers, and packaging.
- [reversible-configuration-changes](.agents/skills/reversible-configuration-changes/SKILL.md)
  - change files, services, journal entries, backups, and `--undo`.
- [firewall-and-boot-safety](.agents/skills/firewall-and-boot-safety/SKILL.md)
  - touch nftables, SSH, sysctl, kernel parameters, or boot entries.
- [mock-based-script-tests](.agents/skills/mock-based-script-tests/SKILL.md)
  - assess or add test coverage without faking real behavior.
