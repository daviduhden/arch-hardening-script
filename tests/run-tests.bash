#!/bin/bash

# Static test suite for hardening.bash.
#
# Exercises the script against a synthetic filesystem tree
# (ARCH_HARDENING_TEST_ROOT) with mocked system tools, covering:
#
#   1. Arch + systemd + GRUB
#   2. Arch + systemd + systemd-boot
#   3. Arch + systemd + Syslinux
#   4. Artix + OpenRC + GRUB
#   5. Artix + runit + GRUB
#   6. Artix + s6 + GRUB
#   7. Artix + dinit + GRUB
#   8. Unsupported distribution
#   9. Idempotence (repeat runs change nothing)
#  10. Undo (--undo restores backed-up state)
#  11. Dry-run (--dry-run modifies nothing)

set -euo pipefail

cd "$(dirname "$0")/.."
ROOTDIR="$(pwd)"
SCRIPT="$ROOTDIR/hardening.bash"
MOCKBIN="$ROOTDIR/tests/mockbin"
CONFIG="$ROOTDIR/tests/config/all-yes.conf"
TMPBASE="$(mktemp -d /tmp/arch-hardening-tests.XXXXXX)"

PASS=0
FAIL=0
TEST_NAME=""

cleanup() {
	rm -rf "$TMPBASE"
}
trap cleanup EXIT

pass() {
	PASS=$((PASS + 1))
	printf 'ok   %s: %s\n' "$TEST_NAME" "$1"
}

fail() {
	FAIL=$((FAIL + 1))
	printf 'FAIL %s: %s\n' "$TEST_NAME" "$1"
}

assert_true() {
	if eval "$1"; then
		pass "$2"
	else
		fail "$2"
	fi
}

assert_false() {
	if ! eval "$1"; then
		pass "$2"
	else
		fail "$2"
	fi
}

# new_env <name> — set up a fresh fixture root and mock state.
new_env() {
	TEST_NAME="$1"
	ENVROOT="$TMPBASE/$1"
	mkdir -p "$ENVROOT"
	: >"$TMPBASE/mock.log"
	: >"$ENVROOT/installed"
	: >"$ENVROOT/enabled"
	: >"$ENVROOT/active"

	export ARCH_HARDENING_TEST_ROOT="$ENVROOT"
	export TEST_ROOT="$ENVROOT"
	export MOCK_LOG="$TMPBASE/mock.log"
	export FAKE_INSTALLED="$ENVROOT/installed"
	export FAKE_ENABLED="$ENVROOT/enabled"
	export FAKE_ACTIVE="$ENVROOT/active"
	export MISSING_MODULES=""
	export PATH="$MOCKBIN:$PATH"
}

# build_fixture <distro> <init> <bootloader> [network-manager]
build_fixture() {
	local distro="$1"
	local init="$2"
	local bl="$3"
	local nm="${4:-networkmanager}"

	# /etc/os-release
	mkdir -p "$ENVROOT/etc"
	printf 'ID=%s\nNAME="Test"\n' "$distro" >"$ENVROOT/etc/os-release"

	# /proc
	mkdir -p "$ENVROOT/proc/1"
	case "$init" in
	systemd) printf 'systemd\n' >"$ENVROOT/proc/1/comm" ;;
	openrc) printf 'init\n' >"$ENVROOT/proc/1/comm" ;;
	runit) printf 'runit\n' >"$ENVROOT/proc/1/comm" ;;
	s6) printf 's6-svscan\n' >"$ENVROOT/proc/1/comm" ;;
	dinit) printf 'dinit\n' >"$ENVROOT/proc/1/comm" ;;
	esac
	printf 'vendor_id\t: GenuineIntel\n' >"$ENVROOT/proc/cpuinfo"
	: >"$ENVROOT/proc/cmdline"
	mkdir -p "$ENVROOT/proc/asound"
	printf '0 snd_hda_intel\n1 snd_usb_audio\n' \
		>"$ENVROOT/proc/asound/modules"

	# init system directories
	case "$init" in
	systemd) mkdir -p "$ENVROOT/run/systemd/system" ;;
	openrc) mkdir -p "$ENVROOT/run/openrc" ;;
	runit) mkdir -p "$ENVROOT/etc/runit/runsvdir/default" ;;
	s6) mkdir -p "$ENVROOT/etc/s6/rc" ;;
	dinit) mkdir -p "$ENVROOT/etc/dinit.d/boot.d" ;;
	esac

	# pacman.conf with an [options]-style preamble and a repo.
	mkdir -p "$ENVROOT/etc/pacman.d"
	cat >"$ENVROOT/etc/pacman.conf" <<'EOF'
[options]
HoldPkg = pacman glibc

[core]
Include = /etc/pacman.d/mirrorlist
EOF

	# PAM: su/su-l with the commented pam_wheel line.
	mkdir -p "$ENVROOT/etc/pam.d"
	for f in su su-l; do
		cat >"$ENVROOT/etc/pam.d/$f" <<'EOF'
#%PAM-1.0
auth            sufficient      pam_rootok.so
#auth           required        pam_wheel.so use_uid
auth            required        pam_unix.so use_uid nullok
EOF
	done

	# sshd, limits, mkinitcpio, hostname
	mkdir -p "$ENVROOT/etc/ssh"
	printf '# sshd_config\nPort 22\n' \
		>"$ENVROOT/etc/ssh/sshd_config"
	mkdir -p "$ENVROOT/etc/security"
	touch "$ENVROOT/etc/security/limits.conf"
	cat >"$ENVROOT/etc/mkinitcpio.conf" <<'EOF'
MODULES=()
BINARIES=()
FILES=()
HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolefont block filesystems fsck)
EOF
	printf 'host\n' >"$ENVROOT/etc/hostname"

	# Network manager presence.
	case "$nm" in
	networkmanager) mkdir -p "$ENVROOT/etc/NetworkManager" ;;
	systemd-networkd) mkdir -p "$ENVROOT/etc/systemd/network" ;;
	iwd) mkdir -p "$ENVROOT/etc/iwd" ;;
	none) : ;;
	esac

	# sshd appears to be running (firewall SSH prompt).
	printf 'sshd\nsshd.service\n' >>"$ENVROOT/active"

	# Bootloader.
	case "$bl" in
	grub)
		mkdir -p "$ENVROOT/boot/grub"
		;;
	systemd-boot)
		mkdir -p "$ENVROOT/boot/loader/entries"
		cat >"$ENVROOT/boot/loader/entries/arch.conf" <<'EOF'
title   Arch Linux
linux   /vmlinuz-linux
initrd  /initramfs-linux.img
options root=UUID=1234 rw quiet
EOF
		;;
	syslinux)
		mkdir -p "$ENVROOT/boot/syslinux"
		cat >"$ENVROOT/boot/syslinux/syslinux.cfg" <<'EOF'
DEFAULT arch
LABEL arch
	MENU LABEL Arch Linux
	LINUX ../vmlinuz-linux
	APPEND root=UUID=1234 rw
	INITRD ../initramfs-linux.img
EOF
		;;
	esac

	# Simulate an already-installed linux-hardened image so the
	# post-install verification passes.
	touch "$ENVROOT/boot/vmlinuz-linux-hardened"
}

# run_script [args...]
run_script() {
	local out
	out="$(bash "$SCRIPT" --config "$CONFIG" "$@" </dev/null 2>&1)" || {
		printf '%s\n' "$out"
		fail "script exited non-zero"
		return 1
	}
	printf '%s\n' "$out" >"$ENVROOT/script.out"
}

# ------------------------------------------------------------------
# 1. Arch + systemd + GRUB
new_env arch-systemd-grub
build_fixture arch systemd grub networkmanager
run_script
S="$ENVROOT"
assert_true "grep -q 'kernel.kptr_restrict=1' $S/etc/sysctl.d/99-arch-hardening.conf" \
	"sysctl: kptr_restrict=1 written"
assert_true "grep -q 'fs.protected_regular=2' $S/etc/sysctl.d/99-arch-hardening.conf" \
	"sysctl: protected_regular=2 written"
assert_false "grep -qE 'dmesg_restrict|tcp_syncookies|unprivileged_userns_clone|unprivileged_bpf_disabled|tcp_sack|icmp_echo_ignore_all' $S/etc/sysctl.d/99-arch-hardening.conf" \
	"sysctl: obsolete settings absent"
assert_true "grep -q 'kernel.perf_event_paranoid=3' $S/etc/sysctl.d/99-arch-hardening.conf" \
	"sysctl: strict perf_event_paranoid=3 written"
assert_true "grep -q 'slab_nomerge' $S/etc/default/grub.d/40-arch-hardening.cfg" \
	"grub: slab_nomerge present in drop-in"
assert_true "grep -q 'lsm=landlock,lockdown,yama,integrity,apparmor,bpf' $S/etc/default/grub.d/40-arch-hardening.cfg" \
	"grub: apparmor lsm= present"
assert_true "grep -q 'ipv6.disable=1' $S/etc/default/grub.d/40-arch-hardening.cfg" \
	"grub: ipv6.disable=1 present"
assert_true "grep -q 'grub-mkconfig' $TMPBASE/mock.log" \
	"grub: grub-mkconfig executed"
assert_true "grep -q 'systemctl .*enable apparmor.service' $TMPBASE/mock.log" \
	"services: apparmor.service enabled"
assert_true "grep -q 'systemctl .*enable nftables.service' $TMPBASE/mock.log" \
	"services: nftables.service enabled"
assert_true "grep -q 'policy drop' $S/etc/nftables.conf" \
	"firewall: default drop policy written"
assert_true "grep -q 'tcp dport 22 accept' $S/etc/nftables.conf" \
	"firewall: ssh exception present"
assert_true "grep -q 'ct state established,related accept' $S/etc/nftables.conf" \
	"firewall: established connections accepted"
assert_true "grep -q 'nd-neighbor-solicit' $S/etc/nftables.conf" \
	"firewall: IPv6 Neighbor Discovery preserved"
assert_true "grep -q 'PermitRootLogin no' $S/etc/ssh/sshd_config.d/99-arch-hardening.conf" \
	"ssh: root login denied via drop-in"
assert_true "grep -q '^auth.*pam_wheel.so use_uid' $S/etc/pam.d/su" \
	"pam: su restricted to wheel"
assert_true "grep -q 'libhardened_malloc.so' $S/etc/ld.so.preload" \
	"hardened_malloc: ld.so.preload configured"
assert_true "grep -q 'vm.max_map_count' $S/etc/sysctl.d/99-arch-hardening-malloc.conf" \
	"hardened_malloc: max_map_count raised"
assert_true "grep -q 'Storage=none' $S/etc/systemd/coredump.conf.d/99-arch-hardening.conf" \
	"coredumps: systemd drop-in written"
assert_true "grep -q 'umask 077' $S/etc/profile.d/99-arch-hardening-umask.sh" \
	"umask: 077 profile script written"
assert_true "grep -q 'allow id 1d6b' $S/etc/usbguard/rules.conf" \
	"usbguard: generated policy written"
assert_true "grep -q 'install firewire-core /bin/true' $S/etc/modprobe.d/99-arch-hardening-dma.conf" \
	"dma: firewire-core blacklisted"
assert_false "grep -q 'thunderbolt' $S/etc/modprobe.d/99-arch-hardening-dma.conf" \
	"dma: obsolete thunderbolt blacklist absent"
assert_true "grep -q 'install uvcvideo /bin/true' $S/etc/modprobe.d/99-arch-hardening-webcam.conf" \
	"webcam: uvcvideo blacklisted"
assert_true "grep -q 'install snd_hda_intel /bin/true' $S/etc/modprobe.d/99-arch-hardening-mic.conf" \
	"mic: detected audio module blacklisted"
assert_true "grep -q 'install btusb /bin/true' $S/etc/modprobe.d/99-arch-hardening-bluetooth.conf" \
	"bluetooth: btusb blacklisted"
assert_true "grep -q 'install sctp /bin/true' $S/etc/modprobe.d/99-arch-hardening-protocols.conf" \
	"protocols: sctp blacklisted"
assert_true "grep -q 'install cramfs /bin/true' $S/etc/modprobe.d/99-arch-hardening-filesystems.conf" \
	"filesystems: cramfs blacklisted"
assert_true "grep -q 'cloned-mac-address=random' $S/etc/NetworkManager/conf.d/90-arch-hardening-mac.conf" \
	"mac: NetworkManager randomization configured"
assert_true "grep -q 'intel-ucode' $ENVROOT/installed" \
	"microcode: intel-ucode installed"
assert_true "grep -q 'apparmor.d-git' $ENVROOT/installed" \
	"apparmor.d: profiles package installed"
assert_true "grep -q 'hardened_malloc' $ENVROOT/installed" \
	"hardened_malloc: package installed"
assert_true "grep -q 'linux-hardened' $ENVROOT/installed" \
	"linux-hardened: package installed"
assert_true "grep -q 'write-cache' $S/etc/apparmor/parser.conf" \
	"apparmor.d: parser caching enabled"
assert_true "grep -q 'chaotic-aur' $S/etc/pacman.conf" \
	"chaotic: repository appended"
assert_true "grep -q 'pacman -U' $TMPBASE/mock.log" \
	"chaotic: keyring packages installed"
assert_true "grep -q 'systemd-timesyncd.service' $ENVROOT/enabled" \
	"time-sync: timesyncd enabled"

# ------------------------------------------------------------------
# 2. Arch + systemd + systemd-boot
new_env arch-systemd-sdboot
build_fixture arch systemd systemd-boot networkmanager
run_script
S="$ENVROOT"
ENTRY="$S/boot/loader/entries/arch.conf"
assert_true "grep -q 'root=UUID=1234' $ENTRY" \
	"systemd-boot: user parameters preserved"
assert_true "grep -q 'slab_nomerge' $ENTRY" \
	"systemd-boot: hardening parameters appended"
assert_true "grep -q 'lsm=.*apparmor' $ENTRY" \
	"systemd-boot: lsm parameter appended"
run_script
assert_true "test \"\$(grep -o 'slab_nomerge' $ENTRY | wc -l)\" -eq 1" \
	"systemd-boot: parameters not duplicated on second run"
assert_true "test \"\$(grep -o 'lsm=' $ENTRY | wc -l)\" -eq 1" \
	"systemd-boot: lsm not duplicated on second run"

# ------------------------------------------------------------------
# 3. Arch + systemd + Syslinux
new_env arch-systemd-syslinux
build_fixture arch systemd syslinux networkmanager
run_script
S="$ENVROOT"
assert_true "grep -q 'APPEND root=UUID=1234 rw slab_nomerge' $S/boot/syslinux/syslinux.cfg" \
	"syslinux: parameters appended to APPEND line"
run_script
assert_true "test \"\$(grep -c 'slab_nomerge' $S/boot/syslinux/syslinux.cfg)\" -eq 1" \
	"syslinux: parameters not duplicated on second run"

# ------------------------------------------------------------------
# 4. Artix + OpenRC + GRUB
new_env artix-openrc-grub
build_fixture artix openrc grub networkmanager
run_script
S="$ENVROOT"
assert_true "grep -q 'rc-update add nftables default' $TMPBASE/mock.log" \
	"openrc: nftables service added to runlevel"
assert_true "grep -q 'rc-update add apparmor default' $TMPBASE/mock.log" \
	"openrc: apparmor service added to runlevel"
assert_true "grep -q 'nftables-openrc' $ENVROOT/installed" \
	"openrc: nftables-openrc package installed"
assert_true "grep -q 'apparmor-openrc' $ENVROOT/installed" \
	"openrc: apparmor-openrc package installed"
assert_true "grep -q 'chrony-openrc' $ENVROOT/installed" \
	"openrc: chrony-openrc package installed"
assert_true "grep -q 'tor-openrc' $ENVROOT/installed" \
	"openrc: tor-openrc package installed"
assert_true "grep -q 'usbguard-openrc' $ENVROOT/installed" \
	"openrc: usbguard-openrc package installed"
assert_false "grep -q 'systemctl' $TMPBASE/mock.log" \
	"openrc: no systemctl invocations"
assert_true "grep -q 'net.ipv4.conf.all.rp_filter=2' $S/etc/sysctl.d/99-arch-hardening.conf" \
	"sysctl: rp_filter loose mode present (Artix parity)"
assert_false "grep -q 'coredump.conf.d' $TMPBASE/mock.log" \
	"coredumps: systemd path not used on openrc"
assert_true "grep -q 'kernel.core_pattern=|/bin/false' $S/etc/sysctl.d/99-arch-hardening-coredumps.conf" \
	"coredumps: sysctl core_pattern written"
assert_true "grep -q '\* hard core 0' $S/etc/security/limits.conf" \
	"coredumps: limits.conf hardened"

# ------------------------------------------------------------------
# 5. Artix + runit + GRUB
new_env artix-runit-grub
build_fixture artix runit grub networkmanager
run_script
S="$ENVROOT"
assert_true "test -L $S/etc/runit/runsvdir/default/nftables" \
	"runit: nftables service symlinked"
assert_true "test -L $S/etc/runit/runsvdir/default/tor" \
	"runit: tor service symlinked"
assert_true "test -L $S/etc/runit/runsvdir/default/chrony" \
	"runit: chrony service symlinked"
assert_false "test -e $S/etc/runit/runsvdir/default/apparmor" \
	"runit: no apparmor service (stage-1 script instead)"
assert_true "grep -q 'apparmor-runit' $ENVROOT/installed" \
	"runit: apparmor-runit package installed"
assert_true "grep -q 'nftables-runit' $ENVROOT/installed" \
	"runit: nftables-runit package installed"

# ------------------------------------------------------------------
# 6. Artix + s6 + GRUB
new_env artix-s6-grub
build_fixture artix s6 grub networkmanager
run_script
assert_true "grep -q 's6-rc-bundle add default nftables' $TMPBASE/mock.log" \
	"s6: nftables service bundled"
assert_true "grep -q 's6-rc-bundle add default tor-srv' $TMPBASE/mock.log" \
	"s6: tor-srv service bundled"
assert_true "grep -q 's6-rc-bundle add default chrony-srv' $TMPBASE/mock.log" \
	"s6: chrony-srv service bundled"
assert_true "grep -q 's6-rc-bundle add default apparmor' $TMPBASE/mock.log" \
	"s6: apparmor service bundled"

# ------------------------------------------------------------------
# 7. Artix + dinit + GRUB (no network manager: macchanger fallback)
new_env artix-dinit-grub
build_fixture artix dinit grub none
run_script
S="$ENVROOT"
assert_true "grep -q 'dinitctl .*enable nftables' $TMPBASE/mock.log" \
	"dinit: nftables service enabled"
assert_true "grep -q 'dinitctl .*enable chronyd' $TMPBASE/mock.log" \
	"dinit: chronyd service enabled"
assert_true "grep -q 'dinitctl .*enable tor' $TMPBASE/mock.log" \
	"dinit: tor service enabled"
assert_true "test -f $S/etc/dinit.d/macspoof" \
	"mac: dinit macspoof service written"
assert_true "test -f $S/usr/lib/arch-hardening-script/spoof-mac-addresses" \
	"mac: spoof script installed"
assert_true "grep -q 'macchanger' $ENVROOT/installed" \
	"mac: macchanger installed"
assert_true "grep -q 'chrony-dinit' $ENVROOT/installed" \
	"dinit: chrony-dinit package installed"

# ------------------------------------------------------------------
# 8. Unsupported distribution must abort
new_env unsupported-distro
build_fixture ubuntu systemd grub networkmanager
if bash "$SCRIPT" --config "$CONFIG" >/dev/null 2>&1; then
	fail "unsupported distro: script exited 0"
else
	pass "unsupported distro: script aborted"
fi

# ------------------------------------------------------------------
# 9. Idempotence: second full run changes nothing
new_env idempotence
build_fixture arch systemd grub networkmanager
run_script
S="$ENVROOT"
assert_true "grep -q 'Changes made:.*[1-9]' $S/script.out" \
	"idempotence: first run made changes"
: >"$TMPBASE/mock.log"
run_script
assert_true "grep -q 'Changes made:.*0' $S/script.out" \
	"idempotence: second run made no changes"
assert_false "grep -q 'grub-mkconfig' $TMPBASE/mock.log" \
	"idempotence: no grub-mkconfig on second run"
assert_false "grep -q 'Wrote:' $S/script.out" \
	"idempotence: no files rewritten"

# ------------------------------------------------------------------
# 10. Undo restores the previous state
new_env undo
build_fixture arch systemd grub networkmanager
run_script
S="$ENVROOT"
assert_true "test -f $S/var/lib/arch-hardening-script/journal" \
	"undo: journal recorded"
run_script --undo
assert_false "test -e $S/etc/sysctl.d/99-arch-hardening.conf" \
	"undo: sysctl file removed"
assert_false "test -e $S/etc/default/grub.d/40-arch-hardening.cfg" \
	"undo: grub drop-in removed"
assert_false "test -e $S/etc/nftables.conf" \
	"undo: nftables.conf removed"
assert_true "grep -q '^#auth.*pam_wheel.so use_uid' $S/etc/pam.d/su" \
	"undo: pam su restored from backup"
assert_false "grep -q 'chaotic-aur' $S/etc/pacman.conf" \
	"undo: pacman.conf restored"
assert_false "test -e $S/var/lib/arch-hardening-script/journal" \
	"undo: journal removed"
assert_true "grep -q 'linux-hardened' $ENVROOT/installed" \
	"undo: packages intentionally left installed"

# ------------------------------------------------------------------
# 11. Dry-run modifies nothing
new_env dry-run
build_fixture arch systemd grub networkmanager
run_script --dry-run
S="$ENVROOT"
assert_true "grep -q 'Dry-run' $S/script.out" \
	"dry-run: output announces dry-run mode"
assert_false "test -e $S/etc/sysctl.d/99-arch-hardening.conf" \
	"dry-run: no sysctl file written"
assert_false "test -e $S/var/lib/arch-hardening-script" \
	"dry-run: no state directory created"
assert_false "test -e $S/etc/nftables.conf" \
	"dry-run: no nftables.conf written"
assert_false "grep -q 'pacman -S --needed' $TMPBASE/mock.log" \
	"dry-run: no packages installed"

# ------------------------------------------------------------------
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
