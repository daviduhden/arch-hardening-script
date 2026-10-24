---
name: mock-based-script-tests
description: Assess test coverage and design safe synthetic tests for the Bash hardening scripts without executing hardening on a live host or faking behavior.
---

# Mock-Based Script Tests

Use this skill when asked whether tests exist, to add coverage, or to
evaluate a proposed mock-based test suite.

## Activation Conditions

- A request mentions `tests/`, mocks, fixtures, CI, `make test`, or a
  test suite.
- A change needs regression coverage for a Bash helper, journal, or
  bootloader branch.
- A reviewer claims that tests pass or that behavior is covered.

## Current State (verify before relying on it)

- There is no `tests/` directory, test runner, Makefile, CI
  configuration, or linter configuration in the current tree.
- The former mock-based suite was removed in commit `7ea62a6`; the
  README development reference was updated. The test-only alternate
  root (`ARCH_HARDENING_TEST_ROOT`) was removed in commit `6d86f6f`.
- The only documented checks are static: `bash -n` and `shellcheck` for
  both scripts. Do not claim a suite ran when only these checks ran.
- All managed paths are absolute. There is no supported alternate-root
  or test-mode switch.

## Procedure

1. Confirm the current state with `git ls-files`, `git log --oneline`,
   and a search for `tests`, `mock`, `ARCH_HARDENING_TEST_ROOT`, and CI
   files. Do not assume a suite exists.
2. If the task is only review, report the absence of tests and the
   static checks performed. Do not invent passing tests.
3. If adding tests is explicitly authorized, design them for a
   disposable VM or container, never the live host. A test that runs
   `hardening.bash` as root on the developer machine is not acceptable.
4. Prefer assertions on real filesystem, journal, and service state in
   the disposable environment over assertions on a mock command log.
   Mock logs can prove that a command was called; they cannot prove
   that the resulting configuration is valid.
5. Mock only external commands that cannot run in the sandbox (for
   example `pacman`, `systemctl`, `grub-mkconfig`, `nft`, `sshd`). Keep
   file helpers real so idempotency and journal behavior are exercised.
6. Do not reintroduce `ARCH_HARDENING_TEST_ROOT` or a path-prefix mode
   without an explicit maintainer decision. It was removed because it
   encouraged tests that did not exercise real paths.
7. Cover at least: first run, second identical run, `--dry-run`,
   `--undo`, unsupported distribution, missing config key, malformed
   config line, each init branch, and each bootloader branch that can be
   simulated safely. Mark branches that cannot be simulated as manual
   checks.
8. Ensure the runner fails on any nonzero script exit, leaves no
   temporary root, and prints a clear "not run" status for skipped
   branches. Never turn a skipped branch into a pass.
9. Update `README.md` only with commands that actually exist. If a test
   runner is added, document its prerequisites and isolation model.

## Validation

- Static: `bash -n hardening.bash`,
  `bash -n spoof-mac-addresses.bash`, `shellcheck` on both, and the same
  checks on any new test runner.
- `git diff --check` and `git status --short`.
- Confirm the diff contains no real hardening run, no package manager
  invocation, and no host configuration change.
- If a disposable environment is used, record the exact image/container
  and cleanup step; do not claim coverage for branches that were only
  inspected statically.

## Common Issues

- A mock suite that asserts "systemctl enable was called" while never
  checking whether the unit file exists or is valid.
- Mocks that hide a real failure because the mock always exits 0.
- `set -e` interactions that make a test pass only when a command is
  missing.
- Tests that write to `/etc`, `/boot`, `/var/lib`, or the real journal.
- Treating `--dry-run` as complete coverage; it still performs
  read-only probes and can skip dependent actions.
- Reintroducing a test root and then claiming production paths were
  tested.
- Reporting a static check as a functional test.

## References

- `README.md`: Development.
- `hardening.bash`: helpers, `--dry-run`, `--undo`, journal.
- Removed suite: commit `7ea62a6` ("Remove mock-based test suite").
- Removed alternate root: commit `6d86f6f`.
- ShellCheck: <https://www.shellcheck.net/>.
