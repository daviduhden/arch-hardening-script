# Arch / Artix Hardening Script

## Overview

`hardening.bash` is an interactive, idempotent hardening and privacy
configuration script for **Arch Linux** and **Artix Linux**. It
applies a set of individually reviewed measures, explains what each
one does before asking, and records every change so it can be
reverted with `--undo`.

The script targets single-user desktop/laptop workstations. It does
**not** attempt to:

* turn a system into a server-grade bastion,
* provide complete anonymity,
* replace disk encryption, secure boot, or system updates,
* or make a system "secure" by itself.

Every measure is an explicit trade-off. The script asks for
confirmation for each one; answering `n` skips it.

## Security Model

The measures are organized as layers (defense in depth):

| Layer              | Examples implemented here                         |
|--------------------|---------------------------------------------------|
| Kernel self-protection | sysctl hardening, boot parameters           |
| Mandatory access control | AppArmor (LSM activation)                  |
| Application isolation | bubblewrap, optional hardened_malloc        |
| Network security   | nftables default-deny inbound firewall        |
| Local permissions  | su restricted to wheel, root account lock, SSH |
| Hardware attack surface | USBGuard, FireWire blacklist, microcode   |
| Privacy            | MAC randomization, IPv6 privacy extensions, umask |

Running a hardening script does not make a system secure. It reduces
exposure and raises the cost of specific attacks. Ongoing security
requires system updates (microcode, kernel, packages), sane account
management, and careful application use.

## Supported Systems

| Component      | Supported                                              |
|----------------|--------------------------------------------------------|
| Distribution   | Arch Linux, Artix Linux (`ID=arch` or `ID=artix`)      |
| Init system    | systemd, OpenRC, runit, s6, dinit                       |
| Bootloader     | GRUB, systemd-boot, Syslinux                            |
| Architectures  | x86_64 (some optional ASLR sysctls are x86_64-only)     |

Notes:

* **systemd-boot without systemd** (an Artix setup): bootloader
  entries are plain text files, so kernel parameters are applied the
  same way; a warning is shown.
* **Artix repositories**: the script installs the companion service
  packages that Artix maintains per init system (e.g.
  `nftables-openrc`, `tor-runit`, `chrony-s6`, `usbguard-dinit`).
  No local service definitions are invented where Artix ships one.
  Exception: the optional macchanger fallback service, which is
  generated for all five init systems.
* **Syslinux** is deprecated on Arch but still present in the
  repositories; its code path is kept but receives less testing.
* **linux-hardened** on Artix lives in the `galaxy` repository,
  which must be enabled.

## Features

Every feature is optional and prompted individually. Use
`--config` (see below) for reproducible runs.

### Kernel hardening: sysctl

| Purpose | Threat mitigated | What changes | Default |
|---------|------------------|--------------|---------|
| Hide kernel pointers | local privilege-escalation info leak | `kernel.kptr_restrict=1` | off on Arch kernel |
| Symlink/hardlink protection | `/tmp`-style TOCTOU races | `fs.protected_symlinks=1`, `fs.protected_hardlinks=1` | kernel default is 0; systemd already sets 1 |
| FIFO/regular-file protection | attacker-controlled file writes | `fs.protected_fifos=2`, `fs.protected_regular=2` | systemd ships 1; 2 also covers group-writable sticky dirs |
| Reverse-path filtering | IP spoofing on multihomed hosts | `net.ipv4.conf.{all,default}.rp_filter=2` (loose, matches systemd's default) | 0 on Artix without systemd |
| ICMP redirect hardening | on-link traffic redirection | `accept_redirects=0`, `secure_redirects=0`, `send_redirects=0` (IPv4 + IPv6) | kernel enables redirects for hosts |

Strict (optional, trade-offs): `kernel.perf_event_paranoid=3`
(breaks unprivileged perf), `kernel.yama.ptrace_scope=2` (breaks
`gdb`/`strace -p` for unprivileged users), `kernel.kexec_load_disabled=1`
(breaks kexec-based reboots), `dev.tty.ldisc_autoload=0` (blocks
runtime line-discipline loading), higher mmap randomization
(`vm.mmap_rnd_bits=32`, x86_64 only).

Deliberately **removed** from the previous version of this project
(audited against current kernel source and Arch defaults):

* `kernel.dmesg_restrict=1` — Arch kernels ship
  `CONFIG_SECURITY_DMESG_RESTRICT=y`; already the default.
* `kernel.unprivileged_bpf_disabled` — Arch kernels ship
  `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`; the sysctl already defaults to 2.
* `kernel.unprivileged_userns_clone` — Debian-only sysctl; does not
  exist on Arch kernels.
* `kernel.sysrq=4` — Arch kernels default to `0x0` (disabled);
  writing 4 would have *enabled* part of Magic SysRq.
* `kernel.printk=3 3 3 3` — cosmetic; hides legitimate warnings.
* `net.ipv4.tcp_syncookies` — kernel default is already 1.
* `net.ipv4.tcp_sack/dsack/fack` — defaults are fine; disabling harms
  throughput; `tcp_fack` is a documented no-op.
* `net.ipv4.icmp_echo_ignore_all` — breaks ping diagnostics; the
  nftables policy already drops unsolicited inbound traffic.
* `net.ipv4.conf.*.accept_source_route` — already 0 (kernel and
  systemd defaults).
* `net.ipv6.conf.*.accept_ra=0` — breaks SLAAC; leave to the
  network manager.
* `vm.unprivileged_userfaultfd=0` — already the kernel default.

The sysctls are written to
`/etc/sysctl.d/99-arch-hardening.conf` and applied at boot by the
init system's sysctl mechanism (systemd, OpenRC, runit, s6 and
dinit all process `/etc/sysctl.d/`).

### Kernel hardening: boot parameters

* Standard: `slab_nomerge` (prevents merging of kernel slabs),
  `init_on_free=1` (zeroes memory on free). Note that the Arch
  kernel already enables `init_on_alloc=1` and
  `randomize_kstack_offset=on` by default, and `linux-hardened`
  enables all three plus `vsyscall=none`, so these parameters
  are mostly redundant there.
* Strict (optional, trade-offs): `vsyscall=none` (breaks very old
  static binaries), `lockdown=confidentiality` (breaks kernel
  tracing tools such as bpftrace and perf kernel profiling),
  `module.sig_enforce=1` (blocks unsigned out-of-tree modules such
  as NVIDIA/ZFS/virtualbox unless signed), `debugfs=off` (breaks
  some diagnostic tools), `oops=panic` (reboots on any kernel
  oops), `mitigations=auto,nosmt` (disables SMT; mainly benefits
  hypervisors, per the Arch Wiki).

Deliberately removed: `pti=on`, `spectre_v2=on`,
`spec_store_bypass_disable=on`, `tsx=off`,
`tsx_async_abort=full,nosmt`, `mds=full,nosmt`,
`mmio_stale_data=full,nosmt`, `l1tf=full,force`, `nosmt=force`,
`retbleed=auto,nosmt`, `kvm.nx_huge_pages=force`,
`page_alloc.shuffle=1`, `quiet loglevel=0`. The kernel already
applies the appropriate mitigations on vulnerable hardware;
`mitigations=auto,nosmt` expresses the only remaining meaningful
choice; `page_alloc.shuffle` is weak next to `init_on_alloc`; and
hiding boot output is not security.

Parameters are accumulated and applied per bootloader:

* **GRUB**: `/etc/default/grub.d/40-arch-hardening.cfg` (sourced by
  GRUB's own `10_linux`, no fragile edits to `/etc/default/grub`),
  then `grub-mkconfig` runs once. Existing administrator parameters
  are preserved; the drop-in only appends.
* **systemd-boot**: parameters are appended idempotently to the
  `options` line of kernel entries under `/boot/loader/entries/`
  (entries for other OSes and non-vmlinuz loaders are skipped).
  Each entry is backed up before editing.
* **Syslinux**: parameters are appended to the `APPEND` line of the
  `MENU LABEL Arch Linux` entry.

### AppArmor

AppArmor is compiled into the Arch/Artix kernels but not enabled in
the default LSM list. The script:

1. installs `apparmor` (and `apparmor-openrc` / `apparmor-s6` /
   `apparmor-dinit` / `apparmor-runit` on Artix),
2. adds
   `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` to the
   kernel parameters (never overwriting an existing administrator
   `lsm=`),
3. enables and starts `apparmor.service` (or the equivalent).

On runit, AppArmor is activated by the stage-1 sysinit script
shipped in `apparmor-runit`; there is no service to enable.

Verify after reboot: `cat /sys/kernel/security/lsm` must list
`apparmor`, and `aa-status` must show loaded profiles.

**Installing AppArmor does not confine anything by itself** — it
only enables the mechanism. Profiles are what do the work.

### AppArmor profiles (apparmor.d)

Optional. Requires the Chaotic-AUR repository (or manual
installation of the `apparmor.d-git` AUR package). The profiles are
loaded in enforce mode. Sources and caveats:

* upstream project: <https://github.com/roddhjav/apparmor.d>
* the Arch Wiki notes the project "is not currently stable" — expect
  occasional breakage; test with `aa-complain <profile>` when an
  application misbehaves.
* the script also enables profile caching (`write-cache`) in
  `/etc/apparmor/parser.conf`.

### nftables firewall

Writes `/etc/nftables.conf` with a default-deny **inbound** policy:

* accept established/related, drop invalid,
* accept loopback,
* accept essential ICMPv4 (echo, unreachable, time-exceeded,
  parameter-problem),
* accept essential ICMPv6 including Neighbor Discovery and MLD so
  that SLAAC and IPv6 keep working,
* drop everything else inbound; forward is always dropped; output
  is not filtered.

The ruleset is validated with `nft -c -f` **before** it is written.
If an SSH daemon is detected as running, the script asks whether to
keep port 22 open to avoid locking out remote administration. The
service is enabled and started (`nftables.service`, or the Artix
init-specific service).

### linux-hardened

Optional. Installs `linux-hardened` and `linux-hardened-headers`
while **keeping your current kernel as a fallback** (no default
entry is rewritten; select the kernel in the boot menu). The
package's mkinitcpio hook regenerates the initramfs; the script
verifies the kernel image exists, then refreshes GRUB (or
`bootctl update` / `extlinux --update`) only on the first install.

Known interactions:

* unprivileged user namespaces are **disabled** in linux-hardened;
  bubblewrap/Flatpak then need the setuid fallback (the script
  offers `chmod u+s /usr/bin/bwrap`, mirroring the former
  `bubblewrap-suid` package).
* out-of-tree modules (NVIDIA, virtualbox, ZFS via DKMS) must be
  built against the new kernel; `lockdown=`/`module.sig_enforce=1`
  additionally require signing.
* kexec is unavailable in linux-hardened; don't combine it with
  `kernel.kexec_load_disabled=1`.

### bubblewrap

Installs `bubblewrap` from the official repositories. A sandboxing
tool alone provides nothing; configure Flatpak/Firejail/your own
wrappers to actually use it. With linux-hardened, see the setuid
note above.

`bubblejail` is not in the official repositories and is no longer
installed automatically; it remains available in the AUR / Chaotic-AUR
for manual installation.

### Chaotic-AUR

Optional and clearly labeled: Chaotic-AUR is an **unofficial
third-party binary repository** that expands pacman's supply-chain
trust boundary. It is offered only as a source for prebuilt
`hardened_malloc` and `apparmor.d` packages, uses the official
Chaotic-AUR signing key (imported over HTTPS packages, never
`TrustAll`, `SigLevel` unchanged), and is made idempotent. Adding
it runs a full `pacman -Syu` afterwards to avoid partial upgrades.
Adding this repository is **not a security improvement**; do not
enable it unless you need one of those packages.

### hardened_malloc

Advanced, optional. `hardened_malloc` is a hardened malloc
replacement. It is **not** in the official repositories — it is
installed from Chaotic-AUR (if enabled) or manually from the AUR.
The script:

* raises `vm.max_map_count` as recommended upstream,
* does **not** preload it globally by default. Global
  `/etc/ld.so.preload` breaks some applications (Electron, some
  games) and costs performance; per-application usage
  (`LD_PRELOAD=/usr/lib/libhardened_malloc.so <app>`) is offered
  instead, with the global preload as an explicit opt-in.

### Microcode

Detects the CPU vendor (`GenuineIntel`/`AuthenticAMD`) and installs
`intel-ucode` or `amd-ucode`. With current mkinitcpio/dracut, the
microcode is embedded in the initramfs automatically; no bootloader
editing is required (the previous script's bootloader surgery was
obsolete). The script only checks that the `microcode` hook is
present in `mkinitcpio.conf` and warns if not.

### Time synchronization

The previous "disable NTP" feature was removed as a security
measure: correct time is security-relevant (package signatures,
TLS, logs, Tor). Instead:

* "Ensure time sync": on systemd, enables `systemd-timesyncd`
  (Arch's default); on Artix, installs and enables `chrony`
  (`chrony-openrc` etc.). For authenticated NTP (NTS), configure
  chrony manually, see the references.
* "Disable network time sync": kept as an explicitly labeled
  **privacy** trade-off (reduced network metadata at the cost of
  weaker security guarantees), not as hardening.

### IPv6

Two independent choices:

* **Disable IPv6** (`ipv6.disable=1`): a network-policy choice to
  remove an attack surface; not a general security requirement and
  not recommended.
* **IPv6 privacy extensions** (`net.ipv6.conf.*.use_tempaddr=2`):
  applied via sysctl, NetworkManager (`ipv6.ip6-privacy=2` drop-in)
  or systemd-networkd (`IPv6PrivacyExtensions=yes`), so temporary
  addresses are preferred. Requires IPv6 to remain enabled.

### MAC address randomization

Privacy, not a security control. Uses the native mechanism of the
detected network manager so it never races with a boot-time script:

* NetworkManager: drop-in setting `wifi.cloned-mac-address` and
  `ethernet.cloned-mac-address` to `random` or `stable`, plus
  `wifi.scan-rand-mac-address=yes`.
* systemd-networkd: `[Link] MACAddressPolicy=random|persistent`.
* iwd: already randomizes per network by default; the script makes
  `AddressRandomization=network` explicit.
* No supported manager (e.g. plain dhcpcd): installs `macchanger`
  plus a small boot service generated for the active init system
  (this is the only case where the script writes its own service).

### Hostname privacy

Two options, both clearly limited:

* set the hostname to the generic `host` — removes one identifier,
  but a static generic hostname can itself become a stable
  identifier and provides no anonymity;
* stop announcing the hostname to DHCP servers
  (NetworkManager `hostname.send-hostname=0`, systemd-networkd
  `SendHostname=no`).

### umask

Choice of `027` (group/traversal-restricted) or `077` (private).
Written as `/etc/profile.d/99-arch-hardening-umask.sh`, affecting
interactive shells only. `077` is a privacy-oriented choice; it can
break software that expects group-readable files.

### Root account restrictions

* **Restrict su to wheel**: idempotently enables the commented
  `pam_wheel.so use_uid` line in `/etc/pam.d/su` and
  `/etc/pam.d/su-l` (or inserts it after `pam_rootok`). The
  obsolete `/etc/securetty` editing was removed (pam_securetty is
  not used by Arch's PAM stack).
* **Lock the root password** (`passwd -l root`): prevents password
  login as root; sudo and console recovery with an admin account
  still work.
* **Deny root SSH login**: writes a drop-in
  `/etc/ssh/sshd_config.d/99-arch-hardening.conf` with
  `PermitRootLogin no`, validates the result with `sshd -t`, and
  never touches `/etc/ssh/sshd_config` itself.

### Coredumps

Strict option, disables core dump storage:

* systemd: `Storage=none` drop-in for systemd-coredump — crashes
  are still recorded in the journal, only core files are not stored.
* Artix (no systemd-coredump): `kernel.core_pattern=|/bin/false`
  plus `* hard core 0` in `/etc/security/limits.conf`.

Keeping coredumps with restricted access is preferable for
diagnostics; this option exists for disk/privacy-sensitive setups.

### USBGuard

Installs `usbguard` and offers to generate an allow-policy from the
currently connected devices (plug in your keyboard, mouse and
trusted devices first). Without a policy, *all* USB devices may be
blocked, including keyboards. The service is enabled and started
(`usbguard.service`, `usbguard-openrc`, …). New devices are denied
until added to the policy (`usbguard append-rule`).

### FireWire blacklist

Blacklists `firewire-core` and `firewire-ohci` (DMA-capable
hardware attack surface). The `thunderbolt` blacklist was removed:
the thunderbolt driver is **not compiled** in current Arch/Artix
kernels, so the old entry did nothing. For stronger protection of
DMA-capable ports, prefer IOMMU and Thunderbolt authorization
(see references) — total module blacklisting is kept as the simple
high-security option.

### Webcam / microphone

Strong hardware-disable policy with real usability consequences:

* webcam: blacklists `uvcvideo` (all UVC webcams);
* microphone/speakers: blacklists the sound modules detected via
  `/proc/asound/modules` (e.g. `snd_hda_intel`) — this silences
  HDMI, analog and USB audio alike. Drivers built into the kernel
  cannot be blacklisted this way.

These are not a substitute for application-level controls
(PipeWire/PulseAudio routing, portal permissions) and do not defend
against firmware-level attacks. Physical covers are the only
complete mitigation.

### Wireless / Bluetooth

* One-shot `rfkill block all` (optionally unblocking Wi-Fi again).
  This is **not persistent** across reboots.
* Persistent Bluetooth disable via modprobe blacklist of `bluetooth`
  and `btusb`. Existing loaded modules stay loaded until reboot.

### Tor

Installs `tor` and starts the SOCKS proxy on `127.0.0.1:9050`
(plus the init-specific service). This does **not** anonymize the
system: only applications explicitly configured to use the SOCKS
port (e.g. via `torsocks`) go through Tor, and Tor is not a
universal fix for DNS leaks.

Optional: route pacman downloads through Tor via an idempotent
`XferCommand` (SOCKShostname, so DNS is resolved by the exit node).
Package integrity remains protected by pacman's PGP signatures.
Adds latency; only HTTPS-capable mirrors should be used (current
mirrorlists are HTTPS by default).

### Uncommon protocol / filesystem blacklists

Both are now short, verified lists. Each module is only blacklisted
when it exists in the running kernel (`modinfo` check); everything
else is reported as skipped.

* Protocols: `sctp`, `rds`, `tipc`, `atm`, `n_hdlc`, `af_802154`.
  Removed entries that are no longer built in Arch kernels (dccp,
  ax25, netrom, x25, rose, decnet, econet, ipx, appletalk,
  p8022/p8023/psnap) and `llc`/`can` (legitimate users).
* Filesystems: `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`,
  `udf`. Removed `squashfs` (required by AppImage/snap), and
  cifs/nfs/ksmbd/gfs2 (legitimate networked storage; mounting them
  already requires privileges).

These are defense-in-depth: loading these modules requires either
local code execution or a socket syscall; the blacklists raise the
cost of exploiting obscure protocol stacks.

### Entropy daemons (removed)

`haveged` and `jitterentropy` installation was removed. Modern
kernels use a cryptographically secure RNG with CPU RDRAND and
built-in jitter entropy (`CONFIG_CRYPTO_JITTERENTROPY=y` on Arch),
so neither daemon provides a benefit on typical desktop/laptop
hardware, and haveged's entropy quality has been debated. On
genuinely entropy-starved headless hardware, `rng-tools` is the
supported approach — configure it manually.

### Netfilter conntrack helpers (removed)

The `nf_conntrack_helper` auto-assignment mechanism was removed
from the kernel (v6.0); helpers have only been assignable via
explicit rules since 4.7. The old modprobe line was a no-op.

## Usage

Do not run code from the Internet blindly. Clone, review, then run:

```sh
git clone https://github.com/daviduhden/arch-hardening-script.git
cd arch-hardening-script
review hardening.bash and README.md
sudo bash hardening.bash
```

Each measure prompts for confirmation. Answer `y` to apply, `n` to
skip, `Ctrl-C` to abort. You are asked to reboot at the end.

## Command-Line Options

| Flag              | Description                                    |
|-------------------|------------------------------------------------|
| `--help`, `-h`    | Show usage.                                    |
| `--dry-run`       | Print the full plan (packages, files, services, sysctls, kernel parameters, firewall) without modifying anything. Does not require root. |
| `--undo`          | Revert configuration changes made by a previous run (see below). |
| `--config FILE`   | Read answers from `FILE` (`KEY=value`, one per line) instead of prompting; suitable for reproducible setups. Not a replacement for review. |
| `--disable-checks`| Skip the distribution compatibility check. Only for advanced users; can produce breakage on other systems. |
| `--version`       | Print the version.                             |

### Configuration keys

All prompt keys from the interactive mode are valid, e.g.:

```
update=no
sysctl=yes
sysctl-strict=no
kernel-params=yes
kernel-params-strict=no
disable-ipv6=no
firewall=yes
firewall-ssh=yes
time-sync=yes
disable-time-sync=no
apparmor=yes
apparmor-profiles=no
linux-hardened=no
bubblewrap=no
bubblewrap-suid=no
chaotic-aur=no
hardened-malloc=no
hardened-malloc-global=no
microcode=yes
restrict-su=yes
lock-root=no
deny-root-ssh=yes
umask=yes
umask-value=027
coredumps=no
usbguard=yes
usbguard-policy=yes
dma=yes
webcam=no
microphone=no
rfkill=no
rfkill-wifi=yes
bluetooth=no
mac=yes
mac-mode=random
hostname=no
dhcp-hostname=yes
tor=no
tor-pacman=no
protocols=no
filesystems=no
reboot=no
```

## Backups and Rollback

Before modifying an existing administrator-controlled file
(`/etc/pacman.conf`, `/etc/pam.d/su`, bootloader entries, …), the
script creates **one** backup next to the file with the suffix
`.arch-hardening.bak` (e.g.
`/etc/pacman.conf.arch-hardening.bak`). Backups are never
overwritten by later runs, so they always represent the state
before this project first touched the file.

Every action is recorded in
`/var/lib/arch-hardening-script/journal`. `--undo` replays that
journal in reverse:

* restores backed-up files,
* removes files created by the script,
* disables services it enabled (and re-enables ones it masked, if
  they were enabled before),
* regenerates the GRUB configuration when it had modified it,
* leaves installed packages in place (uninstalling is left to you;
  `pacman -Rsn <pkg>` for the relevant packages).

Note: sysctl values remain active until reboot, and `--undo`
reverts exactly what a previous run recorded — it cannot restore
state that was changed by other tools in between.

Manual rollback is also simple: every persistent change is one of
the following:

* `/etc/sysctl.d/99-arch-hardening.conf` (and
  `99-arch-hardening-malloc.conf`, `99-arch-hardening-coredumps.conf`)
* `/etc/modprobe.d/99-arch-hardening-*.conf`
* `/etc/default/grub.d/40-arch-hardening.cfg`
* `/etc/NetworkManager/conf.d/90-arch-hardening-*.conf`
* `/etc/systemd/network/99-arch-hardening-*`
* `/etc/systemd/coredump.conf.d/99-arch-hardening.conf`
* `/etc/profile.d/99-arch-hardening-umask.sh`
* `/etc/ssh/sshd_config.d/99-arch-hardening.conf`
* `/etc/nftables.conf`
* service states (`systemctl`/`rc-update`/`dinitctl`/… equivalents)

Remove the relevant file (or restore its `.arch-hardening.bak`)
and reboot.

## Verification

After rebooting, verify what was applied:

```sh
# kernel and parameters
uname -r
cat /proc/cmdline

# LSMs / AppArmor
cat /sys/kernel/security/lsm
aa-status

# sysctl
sysctl kernel.kptr_restrict kernel.perf_event_paranoid \
    fs.protected_regular net.ipv4.conf.all.rp_filter

# firewall
sudo nft list ruleset

# IPv6 (if not disabled)
ip -6 addr

# USBGuard
sudo usbguard list-devices

# microcode (applied early at boot)
journalctl -k --grep='microcode:'   # systemd
dmesg | grep -i microcode           # other init systems

# Bluetooth blacklist state
lsmod | grep -E '^bluetooth|^btusb'   # empty after reboot

# time synchronization
timedatectl                          # systemd
chronyc tracking                     # chrony on Artix
```

## Compatibility Notes

Known breakage when the corresponding option is enabled:

* `lockdown=confidentiality`: bpftrace, perf kernel profiling,
  kprobes, `/dev/mem` access stop working.
* `module.sig_enforce=1`: unsigned DKMS modules (nvidia, zfs,
  virtualbox) stop loading until signed.
* `mitigations=auto,nosmt`: up to ~30% performance loss on
  SMT-capable CPUs; mostly relevant for virtualization hosts.
* `vsyscall=none`: very old statically linked binaries (including
  some container images) crash.
* `oops=panic`: any driver oops reboots the machine.
* `kernel.yama.ptrace_scope=2`: `gdb`, `strace -p` fail for
  unprivileged users.
* `kernel.perf_event_paranoid=3`: unprivileged `perf` is blocked.
* `fs.protected_regular=2`: writes by others into group-writable
  sticky directories are denied.
* umask `077`: group-shared workflows break.
* audio blacklist: all audio through the blacklisted drivers stops.
* Bluetooth blacklist: Bluetooth is unavailable until unblocked.
* hardened_malloc global preload: Electron-based apps and various
  games may crash; per-application use avoids this.
* linux-hardened: no unprivileged user namespaces (Flatpak/
  bubblewrap need the setuid fallback), kexec unavailable.

## Security Limitations

This script cannot protect against:

* firmware/BIOS implants and physical access,
* malicious or vulnerable applications running as your user,
* supply-chain attacks (including via any added third-party
  repository),
* social engineering,
* an attacker who obtains root (AppArmor mitigates, not prevents),
* poor security habits (updates, backups, password reuse).

## References

* Linux kernel documentation:
  <https://docs.kernel.org/admin-guide/sysctl/kernel.html>,
  <https://docs.kernel.org/admin-guide/sysctl/fs.html>,
  <https://docs.kernel.org/admin-guide/kernel-parameters.html>,
  <https://docs.kernel.org/networking/ip-sysctl.html>,
  <https://docs.kernel.org/admin-guide/hw-vuln/>
* Arch kernel configs (verified during this audit):
  <https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/blob/main/config.x86_64>,
  <https://gitlab.archlinux.org/archlinux/packaging/packages/linux-hardened/-/blob/main/config.x86_64>
* ArchWiki: Security, AppArmor, Microcode, Nftables, NetworkManager
* Artix package database (service packages):
  <https://packages.artixlinux.org/>
* AppArmor: <https://apparmor.net/>, apparmor.d project
  <https://github.com/roddhjav/apparmor.d>
* nftables: <https://wiki.nftables.org/>
* hardened_malloc: <https://github.com/GrapheneOS/hardened_malloc>
* bubblewrap: <https://github.com/containers/bubblewrap>
* USBGuard: <https://usbguard.github.io/>
* chrony (NTS): <https://chrony-project.org/>
* Tor: <https://support.torproject.org/>

## Development

Static testing is available and run in CI-free fashion:

```sh
bash -n hardening.bash
shellcheck hardening.bash
bash tests/run-tests.bash
```

The test suite runs the script against a synthetic filesystem
(no root required) with mocked pacman/systemctl/rc-service/sv/
s6-rc/dinitctl/grub-mkconfig/bootctl/nft/sysctl/modprobe and
covers the supported init systems, bootloaders, idempotence,
`--undo` and `--dry-run`.
