#!/bin/bash

# Arch / Artix hardening script.
# Copyright (C) 2019 madaidan
# Copyright (C) 2025-2026 David Uhden Collado
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -euo pipefail

VERSION="2.0.4"
PROJECT_NAME="arch-hardening-script"
STATE_DIR="/var/lib/arch-hardening-script"
JOURNAL="$STATE_DIR/journal"
BACKUP_SUFFIX=".arch-hardening.bak"

# sysctl / kernel parameter sets managed by this script.
SYSCTL_FILE="etc/sysctl.d/99-arch-hardening.conf"
MODPROBE_PREFIX="etc/modprobe.d/99-arch-hardening"
# Legacy GRUB drop-in path (GRUB never reads it); removed if found.
GRUB_DROPIN="etc/default/grub.d/40-arch-hardening.cfg"

# ---- global state -------------------------------------------------
DRY_RUN=0
DISABLE_CHECKS=0
CONFIG_FILE=""
DO_UNDO=0
IN_UNDO=0 # set while --undo replays the journal
ANSWER="" # result of the last ask() call

declare -A CONFIG_ANSWERS

init_system=""
bootloader=""
distro_id=""
network_manager=""
cpu_vendor=""
kernel_params="" # accumulated kernel command-line additions
SYSCTL_LINES=""  # accumulated sysctl lines
nft_allow_ssh=""
nft_ssh_ports=""
linux_hardened_requested=0
apparmor_requested=0
chaotic_aur_requested=0
CHANGES=0

# ---- logging ------------------------------------------------------
log() {
	printf '%s [INFO] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}
warn() {
	printf '%s [WARN] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}
error() {
	printf '%s [ERROR] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}
fatal() {
	error "$*"
	exit 1
}

# ---- option parsing ----------------------------------------------
parse_arguments() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--dry-run)
			DRY_RUN=1
			shift
			;;
		--undo)
			DO_UNDO=1
			shift
			;;
		--config)
			if [ $# -lt 2 ]; then
				fatal "--config requires a file argument."
			fi
			CONFIG_FILE="$2"
			shift 2
			;;
		--disable-checks)
			DISABLE_CHECKS=1
			shift
			;;
		--version)
			printf '%s %s\n' "$PROJECT_NAME" "$VERSION"
			exit 0
			;;
		--help | -h)
			cat <<EOF
Usage: ${0##*/} [OPTIONS]

Harden an Arch Linux or Artix Linux installation.

Options:
  --dry-run         Print every planned change without applying
                    anything. No root privileges are required.
  --undo            Revert configuration changes made by a
                    previous run of this script (installed
                    packages are left in place).
  --config FILE     Read yes/no answers from FILE (KEY=value,
                    one per line) instead of prompting. See the
                    README for the full list of keys.
  --disable-checks  Skip distribution compatibility checks.
                    Only for advanced users.
  --version         Print the version and exit.
  --help, -h        Show this help message.
EOF
			exit 0
			;;
		*)
			fatal "'$1' is not a recognized flag."
			;;
		esac
	done
}

# ---- interactive prompting ---------------------------------------
# ask <key> <prompt...>
# Sets ANSWER to "y" or "n" (or the configured value).
ask() {
	local key="$1"
	shift
	local configured="${CONFIG_ANSWERS[$key]:-}"
	if [ -n "$configured" ]; then
		ANSWER="$configured"
		log "Config $key=$configured"
		return 0
	fi
	if [ "$DRY_RUN" = "1" ]; then
		ANSWER="y"
		log "Dry-run: assuming yes for: $*"
		return 0
	fi
	read -r -p "$* (y/n) " ANSWER || ANSWER=""
	ANSWER="${ANSWER:-n}"
}

# ask_choice <key> <prompt> <choice1> <choice2> [choice3...]
# Sets ANSWER to one of the choices.
ask_choice() {
	local key="$1"
	shift
	local prompt="$1"
	shift
	local configured="${CONFIG_ANSWERS[$key]:-}"
	if [ -n "$configured" ]; then
		local c
		for c in "$@"; do
			if [ "$configured" = "$c" ]; then
				ANSWER="$configured"
				log "Config $key=$configured"
				return 0
			fi
		done
		warn "Invalid value for $key: '$configured' (expected:" \
			"$*); prompting instead."
	fi
	if [ "$DRY_RUN" = "1" ]; then
		ANSWER="$1"
		log "Dry-run: choosing $1 for: $prompt"
		return 0
	fi
	while :; do
		printf '%s (%s) ' "$prompt" "$*"
		if ! read -r ANSWER; then
			warn "End of input; choosing $1."
			ANSWER="$1"
			return 0
		fi
		local c
		for c in "$@"; do
			if [ "$ANSWER" = "$c" ]; then
				return 0
			fi
		done
		warn "Please answer with one of: $*"
	done
}

is_yes() {
	case "$1" in
	y | Y | yes | YES | 1 | true | TRUE) return 0 ;;
	esac
	return 1
}

# Load KEY=value pairs from a configuration file.
load_config_file() {
	[ -n "$CONFIG_FILE" ] || return 0
	if [ ! -r "$CONFIG_FILE" ]; then
		fatal "Cannot read config file: $CONFIG_FILE"
	fi
	local line key value
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		"" | \#*) continue ;;
		*=*) ;;
		*)
			warn "Ignoring malformed config line (no '='):" \
				"$line"
			continue
			;;
		esac
		key="${line%%=*}"
		value="${line#*=}"
		key="$(printf '%s' "$key" | tr -d '[:space:]')"
		# Tolerate CRLF endings, surrounding whitespace and
		# optional quotes around the value.
		value="${value%$'\r'}"
		value="${value#"${value%%[![:space:]]*}"}"
		value="${value%"${value##*[![:space:]]}"}"
		case "$value" in
		\"*\")
			value="${value#\"}"
			value="${value%\"}"
			;;
		\'*\')
			value="${value#\'}"
			value="${value%\'}"
			;;
		esac
		if [ -z "$key" ]; then
			warn "Ignoring malformed config line: $line"
			continue
		fi
		CONFIG_ANSWERS[$key]="$value"
	done <"$CONFIG_FILE"
}

# ---- state journal (for --undo) ----------------------------------
journal_add() {
	[ "$DRY_RUN" = "0" ] || return 0
	# Never grow the journal while --undo is replaying it: doing so
	# could extend the file being read and make the loop re-process
	# newly appended entries.
	[ "$IN_UNDO" = "0" ] || return 0
	mkdir -p "$STATE_DIR"
	printf '%s\n' "$*" >>"$JOURNAL"
}

journal_has() {
	[ -f "$JOURNAL" ] && grep -qxF "$*" "$JOURNAL"
}

# ---- filesystem helpers ------------------------------------------
# FILE_CHANGED is set by write_file: 1 when the file was (or, in
# dry-run mode, would be) written, 0 when it was already correct.
FILE_CHANGED=0

# write_file <path> <content>
# Writes the file only when its content differs. Backs up an
# existing administrator-owned file exactly once. Journals the
# change so --undo can reverse it. Returns 0 in both cases; check
# FILE_CHANGED to learn whether anything was modified.
write_file() {
	local path="$1"
	local content="$2"
	FILE_CHANGED=0

	if [ -f "$path" ] && [ "$(cat "$path")" = "$content" ]; then
		log "Unchanged: $path"
		return 0
	fi

	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would write $path"
		FILE_CHANGED=1
		CHANGES=$((CHANGES + 1))
		return 0
	fi

	mkdir -p "$(dirname "$path")"

	# A file that already exists is administrator-owned: back it up
	# (once) so --undo can restore it. Only a file this script
	# creates gets a "C" (created) journal entry; recording both "M"
	# and "C" for the same path would make --undo delete a file it
	# should restore.
	local existed=0
	if [ -f "$path" ]; then
		existed=1
		if ! journal_has "C	$path"; then
			backup_existing "$path"
		fi
	fi

	local mode="0644"
	if [ -f "$path" ]; then
		mode="$(stat -c '%a' "$path")"
	fi

	local tmp
	tmp="$(make_tempfile)"
	printf '%s\n' "$content" >"$tmp"
	local owner_args=()
	if [ "$(id -u)" = "0" ]; then
		owner_args=(-o root -g root)
	fi
	if ! install -m "$mode" "${owner_args[@]}" "$tmp" "$path"; then
		fatal "Failed to write $path"
	fi
	rm -f "$tmp"

	if [ "$existed" = "0" ] && ! journal_has "C	$path"; then
		journal_add "C	$path"
	fi
	log "Wrote: $path"
	FILE_CHANGED=1
	CHANGES=$((CHANGES + 1))
	return 0
}

# backup_existing <path>
# Backs up an administrator-owned file once, before a targeted edit.
backup_existing() {
	local path="$1"
	[ -f "$path" ] || return 1
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would edit $path"
		return 0
	fi
	local backup="${path}${BACKUP_SUFFIX}"
	if [ ! -e "$backup" ]; then
		cp -a "$path" "$backup"
	fi
	if ! journal_has "M	$path	$backup"; then
		journal_add "M	$path	$backup"
	fi
	return 0
}

# append_line_if_missing <path> <line>
# Idempotently appends one line to a file, creating the file when
# it does not exist yet.
append_line_if_missing() {
	local path="$1"
	local line="$2"
	local full="${path}"
	if [ -f "$full" ]; then
		if grep -qxF "$line" "$full"; then
			return 0
		fi
	else
		write_file "$path" "$line"
		return 0
	fi
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would append to $full: $line"
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	# A file this script created is removed by --undo, so no backup
	# is needed (and restoring a partial backup after removal would
	# leave the file behind).
	if ! journal_has "C	$full"; then
		backup_existing "$path"
	fi
	# Never concatenate the new line onto a file that lacks a
	# final newline.
	if [ -s "$full" ] && [ -n "$(tail -c 1 "$full" 2>/dev/null)" ]; then
		printf '\n' >>"$full"
	fi
	printf '%s\n' "$line" >>"$full"
	log "Appended to $full: $line"
	CHANGES=$((CHANGES + 1))
}

# ---- command execution -------------------------------------------
# TMP_FILES tracks temporary files so a trap can remove them even
# when the script is interrupted.
TMP_FILES=""
cleanup() {
	local f
	for f in $TMP_FILES; do
		rm -f "$f"
	done
}
trap cleanup EXIT

# tempfile — create a tracked temporary file.
make_tempfile() {
	local f
	f="$(mktemp)"
	TMP_FILES="$TMP_FILES $f"
	printf '%s\n' "$f"
}

# exec_ok <cmd...>
# Executes a command, or merely reports it in dry-run mode.
exec_ok() {
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: $*"
		return 0
	fi
	"$@"
}

# ---- package management ------------------------------------------
pkg_installed() {
	pacman -Qq -- "$1" >/dev/null 2>&1
}

# install_pkgs <pkg...>
# Installs missing packages without refreshing the package
# database. A full system upgrade is still required before
# installing packages on Arch; the caller is responsible for
# warning when the user declined it. Returns 1 on failure.
install_pkgs() {
	local missing=()
	local pkg
	for pkg in "$@"; do
		pkg_installed "$pkg" || missing+=("$pkg")
	done
	if [ "${#missing[@]}" -eq 0 ]; then
		return 0
	fi
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: pacman -S --needed --noconfirm" \
			"${missing[*]}"
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	log "Installing packages: ${missing[*]}"
	if ! pacman -S --needed --noconfirm "${missing[@]}"; then
		error "Failed to install: ${missing[*]}"
		return 1
	fi
	journal_add "I	${missing[*]}"
	CHANGES=$((CHANGES + 1))
}

# install_pkgs_optional <pkg...>
# Like install_pkgs, but a failure only produces a warning and never
# aborts the caller (its return value must stay 0 under `set -e`).
install_pkgs_optional() {
	install_pkgs "$@" ||
		warn "Optional package installation failed; continuing."
}

# ---- system detection --------------------------------------------
detect_distro() {
	if [ "$DISABLE_CHECKS" = "1" ]; then
		distro_id="unknown"
		warn "Compatibility checks disabled."
		return 0
	fi
	if [ ! -r "/etc/os-release" ]; then
		fatal "Cannot read /etc/os-release."
	fi
	distro_id="$(
		grep -E '^ID=' "/etc/os-release" |
			cut -d= -f2 | tr -d '"' || true
	)"
	case "$distro_id" in
	arch | artix) : ;;
	*)
		fatal "This script supports Arch Linux and Artix Linux" \
			"only (detected ID: ${distro_id:-none})."
		;;
	esac
}

detect_init() {
	local pid1=""
	pid1="$(cat "/proc/1/comm" 2>/dev/null || true)"
	case "$pid1" in
	systemd)
		init_system="systemd"
		;;
	runit)
		init_system="runit"
		;;
	s6-svscan)
		init_system="s6"
		;;
	dinit)
		init_system="dinit"
		;;
	init | openrc-init)
		init_system="openrc"
		;;
	*)
		# Fall back to runtime directories and tools.
		if [ -d "/run/systemd/system" ]; then
			init_system="systemd"
		elif [ -d "/run/openrc" ]; then
			init_system="openrc"
		elif [ -d "/etc/runit/runsvdir" ]; then
			init_system="runit"
		elif [ -d "/etc/s6/rc" ] ||
			command -v s6-svscan >/dev/null 2>&1; then
			init_system="s6"
		elif [ -d "/etc/dinit.d" ]; then
			init_system="dinit"
		else
			init_system="unknown"
		fi
		;;
	esac
	if [ "$init_system" = "unknown" ]; then
		fatal "Could not detect the init system. Supported:" \
			"systemd, OpenRC, runit, s6, dinit."
	fi
	log "Detected init system: $init_system"
}

detect_bootloader() {
	if [ -d "/boot/grub" ] &&
		command -v grub-mkconfig >/dev/null 2>&1; then
		bootloader="grub"
	elif command -v bootctl >/dev/null 2>&1 &&
		bootctl is-installed >/dev/null 2>&1; then
		bootloader="systemd-boot"
	elif [ -f "/boot/syslinux/syslinux.cfg" ]; then
		bootloader="syslinux"
	else
		bootloader="none"
	fi
	log "Detected bootloader: $bootloader"
	if [ "$bootloader" = "systemd-boot" ] &&
		[ "$init_system" != "systemd" ]; then
		warn "systemd-boot is in use without systemd as init." \
			"Kernel entries are plain text and are edited" \
			"directly; verify them before rebooting."
	fi
}

detect_network_manager() {
	# Base detection on configuration directories rather than
	# command existence, so the choice reflects what actually
	# manages the interfaces.
	network_manager="none"
	if [ -d "/etc/NetworkManager" ]; then
		network_manager="networkmanager"
	elif [ -d "/etc/systemd/network" ]; then
		network_manager="systemd-networkd"
	elif [ -d "/etc/iwd" ]; then
		network_manager="iwd"
	fi
	log "Detected network management: $network_manager"
}

detect_cpu_vendor() {
	cpu_vendor="$(
		grep -m1 -oE 'GenuineIntel|AuthenticAMD' \
			"/proc/cpuinfo" 2>/dev/null || true
	)"
	case "$cpu_vendor" in
	GenuineIntel) cpu_vendor="intel" ;;
	AuthenticAMD) cpu_vendor="amd" ;;
	*) cpu_vendor="" ;;
	esac
}

# ---- service management (per init system) ------------------------
svc_is_enabled() {
	local svc="$1"
	case "$init_system" in
	systemd)
		systemctl is-enabled --quiet "$svc"
		;;
	openrc)
		rc-update show 2>/dev/null | grep -qw "$svc"
		;;
	runit)
		[ -e "/etc/runit/runsvdir/default/$svc" ] ||
			[ -L "/etc/runit/runsvdir/default/$svc" ]
		;;
	s6)
		[ -e "/etc/s6/adminsv/default/contents.d/$svc" ] ||
			[ -e "/etc/s6/sv/default/contents.d/$svc" ]
		;;
	dinit)
		[ -e "/etc/dinit.d/boot.d/$svc" ]
		;;
	esac
}

# Only systemd has a real mask concept; the other init systems use
# stop+disable as an approximation.
svc_is_masked() {
	local svc="$1"
	[ "$init_system" = "systemd" ] || return 1
	systemctl is-enabled "$svc" 2>/dev/null | grep -qx 'masked'
}

svc_enable() {
	local svc="$1"
	if svc_is_enabled "$svc"; then
		log "Service already enabled: $svc"
		return 0
	fi
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would enable service $svc"
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	case "$init_system" in
	systemd)
		systemctl enable "$svc"
		;;
	openrc)
		rc-update add "$svc" default
		;;
	runit)
		ln -sfn "/etc/runit/sv/$svc" \
			"/etc/runit/runsvdir/default/$svc"
		;;
	s6)
		mkdir -p "/etc/s6/adminsv/default/contents.d"
		: >"/etc/s6/adminsv/default/contents.d/$svc"
		s6-db-reload ||
			warn "s6-db-reload failed; reboot to apply."
		;;
	dinit)
		dinitctl enable "$svc"
		;;
	esac
	journal_add "S+	$svc"
	log "Enabled service: $svc"
	CHANGES=$((CHANGES + 1))
}

svc_start() {
	local svc="$1"
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would start service $svc"
		return 0
	fi
	case "$init_system" in
	systemd)
		systemctl start "$svc"
		;;
	openrc)
		rc-service "$svc" start
		;;
	runit)
		sv up "$svc" 2>/dev/null || true
		;;
	s6)
		s6-rc -u change "$svc" 2>/dev/null || true
		;;
	dinit)
		dinitctl start "$svc" 2>/dev/null || true
		;;
	esac
}

svc_enable_now() {
	svc_enable "$1"
	svc_start "$1"
}

svc_disable() {
	local svc="$1"
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would disable service $svc"
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	case "$init_system" in
	systemd)
		systemctl disable "$svc"
		;;
	openrc)
		rc-update del "$svc" default 2>/dev/null || true
		;;
	runit)
		rm -f "/etc/runit/runsvdir/default/$svc"
		;;
	s6)
		rm -f "/etc/s6/adminsv/default/contents.d/$svc"
		s6-db-reload ||
			warn "s6-db-reload failed; reboot to apply."
		;;
	dinit)
		dinitctl disable "$svc" 2>/dev/null || true
		;;
	esac
	log "Disabled service: $svc"
	CHANGES=$((CHANGES + 1))
}

svc_mask() {
	local svc="$1"
	local prev_enabled="0"
	local prev_masked="0"
	svc_is_enabled "$svc" && prev_enabled="1"
	svc_is_masked "$svc" && prev_masked="1"
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would mask service $svc"
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	case "$init_system" in
	systemd)
		systemctl mask --now "$svc"
		;;
	openrc)
		rc-service "$svc" stop 2>/dev/null || true
		rc-update del "$svc" default 2>/dev/null || true
		;;
	runit)
		sv stop "$svc" 2>/dev/null || true
		rm -f "/etc/runit/runsvdir/default/$svc"
		;;
	s6)
		s6-rc -d change "$svc" 2>/dev/null || true
		rm -f "/etc/s6/adminsv/default/contents.d/$svc"
		s6-db-reload ||
			warn "s6-db-reload failed; reboot to apply."
		;;
	dinit)
		dinitctl stop "$svc" 2>/dev/null || true
		dinitctl disable "$svc" 2>/dev/null || true
		;;
	esac
	journal_add "S-	$svc	$prev_enabled	$prev_masked"
	log "Masked service: $svc"
	CHANGES=$((CHANGES + 1))
}

# svc_unmask <svc>
# Reverses a systemd mask recorded by svc_mask. Other init systems
# have no mask concept, so this is a no-op there.
svc_unmask() {
	local svc="$1"
	case "$init_system" in
	systemd)
		if [ "$DRY_RUN" = "1" ]; then
			log "Dry-run: would unmask $svc"
			return 0
		fi
		systemctl unmask "$svc" 2>/dev/null || true
		;;
	esac
}

# The package that provides the init-specific service definition
# on Artix, e.g. "nftables-openrc".
init_service_pkg() {
	printf '%s-%s' "$1" "$init_system"
}

# The service name to control for a given daemon, per init system.
# The s6 names come from the Artix s6 service packages
# (e.g. tor-srv); the dinit chrony daemon is "chronyd"; systemd
# units carry the .service suffix.
service_name_for() {
	case "$1:$init_system" in
	tor:s6) printf 'tor-srv' ;;
	chrony:s6) printf 'chrony-srv' ;;
	chrony:dinit) printf 'chronyd' ;;
	*:systemd) printf '%s.service' "$1" ;;
	*) printf '%s' "$1" ;;
	esac
}

# ---- kernel parameter accumulation -------------------------------
# kernel_param_add <param>
# Adds a kernel parameter, deduplicating by parameter key.
# Keep one staged value per kernel-parameter key. If separate feature choices
# request the same key, the first value remains the one that will be applied.
kernel_param_add() {
	local param="$1"
	local key="${param%%=*}"
	local existing
	for existing in $kernel_params; do
		if [ "${existing%%=*}" = "$key" ]; then
			log "Kernel parameter already staged: $param"
			return 0
		fi
	done
	kernel_params="$kernel_params $param"
}

# Escape extended-regular-expression metacharacters before matching a key in
# the whitespace-delimited kernel command line.
param_key_regex() {
	printf '%s' "$1" | sed 's/[][\\.^$*+?(){}|]/\\&/g'
}

# Does the given line already contain the parameter?
line_has_param() {
	local line="$1"
	local param="$2"
	local key="${param%%=*}"
	local key_re
	key_re="$(param_key_regex "$key")"
	# Presence is checked by key only; an existing key with a different value
	# also counts as present and is left unchanged.
	# Kernel command lines may separate options with tabs.
	printf '%s\n' " $(printf '%s' "$line" | tr '\t' ' ') " |
		grep -qE " ${key_re}(=| |$)"
}

# ---- bootloader application --------------------------------------
apply_kernel_params() {
	if [ -z "${kernel_params## }" ]; then
		return 0
	fi
	log "Applying kernel parameters:$kernel_params"

	case "$bootloader" in
	grub)
		apply_grub_params
		;;
	systemd-boot)
		apply_systemd_boot_params
		;;
	syslinux)
		apply_syslinux_params
		;;
	none)
		warn "No supported bootloader detected. Add these" \
			"kernel parameters to your boot configuration" \
			"manually:$kernel_params"
		;;
	esac
}

apply_grub_params() {
	local grub_default="/etc/default/grub"
	local dropin="/$GRUB_DROPIN"
	if [ ! -f "$grub_default" ]; then
		warn "No $grub_default found; add these kernel" \
			"parameters manually:$kernel_params"
		return 0
	fi

	# GRUB only reads /etc/default/grub; it does not process
	# /etc/default/grub.d, so extend GRUB_CMDLINE_LINUX there.
	local begin="# >>> $PROJECT_NAME >>>"
	local end="# <<< $PROJECT_NAME <<<"
	local line
	line="GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX$kernel_params\""

	# Remove the obsolete drop-in written by older versions.
	if [ -f "$dropin" ] &&
		grep -qF "Managed by $PROJECT_NAME" "$dropin"; then
		if [ "$DRY_RUN" = "1" ]; then
			log "Dry-run: would remove obsolete $dropin"
		else
			# Keep a restorable copy so --undo does not
			# silently lose an administrator-visible file.
			backup_existing "$dropin" || true
			rm -f "$dropin"
			log "Removed obsolete $dropin"
		fi
	fi

	if grep -qxF "$begin" "$grub_default" &&
		grep -qxF "$line" "$grub_default" &&
		grep -qxF "$end" "$grub_default"; then
		log "GRUB parameters already configured."
		return 0
	fi
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would update $grub_default"
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	backup_existing "/etc/default/grub"
	# Replace any previous managed block, then append the current
	# one; the earlier GRUB_CMDLINE_LINUX definition is preserved.
	sed -i "/^${begin}$/,/^${end}$/d" "$grub_default"
	{
		printf '%s\n' "$begin"
		printf '%s\n' "$line"
		printf '%s\n' "$end"
	} >>"$grub_default"
	log "Added kernel parameters to $grub_default."
	CHANGES=$((CHANGES + 1))
	local grub_cfg="/boot/grub/grub.cfg"
	if [ -f "$grub_cfg" ]; then
		backup_existing "$grub_cfg" || true
	fi
	if ! exec_ok grub-mkconfig -o "$grub_cfg"; then
		# Put the source configuration back; a half-written
		# grub.cfg is worse than the previous one.
		if [ -e "${grub_default}${BACKUP_SUFFIX}" ]; then
			cp -a "${grub_default}${BACKUP_SUFFIX}" \
				"$grub_default" 2>/dev/null || true
		fi
		if [ -e "${grub_cfg}${BACKUP_SUFFIX}" ]; then
			cp -a "${grub_cfg}${BACKUP_SUFFIX}" \
				"$grub_cfg" 2>/dev/null || true
		fi
		fatal "grub-mkconfig failed. The previous GRUB" \
			"configuration was restored from backup."
	fi
	journal_add "G"
	log "Regenerated GRUB configuration."
}

# Print the APPEND lines that belong to the Arch or Artix Linux
# menu entry. Syslinux configurations differ between distributions;
# both labels are handled.
syslinux_target_appends() {
	local cfg="$1"
	awk '
		/^[[:space:]]*MENU LABEL/ {
			if ($0 ~ /(Arch|Artix)([[:space:]]+Linux)?[[:space:]]*$/) {
				in_target = 1
			} else {
				in_target = 0
			}
			next
		}
		in_target && /^[[:space:]]*APPEND[[:space:]]/ { print }
		in_target && /^[[:space:]]*$/ { in_target = 0 }
	' "$cfg"
}

apply_systemd_boot_params() {
	local entry found="" dir
	local entry_dirs=(
		"/boot/loader/entries"
		"/efi/loader/entries"
		"/boot/efi/loader/entries"
	)
	for dir in "${entry_dirs[@]}"; do
		[ -d "$dir" ] || continue
		for entry in "$dir"/*.conf; do
			[ -e "$entry" ] || continue
			if ! grep -qE '^[[:space:]]*linux[[:space:]]' \
				"$entry" 2>/dev/null; then
				continue
			fi
			if ! grep -q 'vmlinuz' "$entry" 2>/dev/null; then
				continue
			fi
			found="1"
			update_entry_options "$entry"
		done
	done
	if [ -z "$found" ]; then
		warn "No systemd-boot kernel entries found under" \
			"/boot/loader/entries/, /efi/loader/entries/" \
			"or /boot/efi/loader/entries/."
	fi
}

update_entry_options() {
	local entry_path="$1"
	local entry="${entry_path}"
	local line missing param
	line="$(grep -m1 -E '^[[:space:]]*options([[:space:]]|$)' \
		"$entry" 2>/dev/null || true)"
	[ -n "$line" ] || line="options"
	# Drop indentation before rebuilding the line; the sed
	# replacement below re-adds it.
	line="${line#"${line%%[![:space:]]*}"}"
	missing=""
	for param in $kernel_params; do
		if ! line_has_param "$line" "$param"; then
			missing="$missing $param"
		fi
	done
	if [ -z "${missing## }" ]; then
		log "Unchanged: $entry"
		return 0
	fi
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would add to $entry:$missing"
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	backup_existing "$entry_path"
	local newline="${line}${missing}"
	local newline_esc
	newline_esc="$(printf '%s' "$newline" |
		sed 's|[&\\|]|\\&|g')"
	if grep -qE '^[[:space:]]*options([[:space:]]|$)' "$entry"; then
		# Preserve indentation and replace every options line so
		# an entry cannot keep a stale, conflicting copy.
		sed -i -E \
			"s|^([[:space:]]*)options([[:space:]].*)?$|\1${newline_esc}|" \
			"$entry"
	else
		# Never concatenate a new options line onto a file that
		# lacks a final newline.
		if [ -s "$entry" ] &&
			[ -n "$(tail -c 1 "$entry" 2>/dev/null)" ]; then
			printf '\n' >>"$entry"
		fi
		printf '%s\n' "$newline" >>"$entry"
	fi
	log "Updated: $entry"
	CHANGES=$((CHANGES + 1))
}

apply_syslinux_params() {
	local cfg="/boot/syslinux/syslinux.cfg"
	if [ ! -f "$cfg" ]; then
		warn "Syslinux configuration not found at $cfg."
		return 0
	fi
	# Only the Arch/Artix Linux entry is ours to edit. Checking the
	# whole file would let a parameter in another label hide a
	# missing parameter in this one.
	local target
	target="$(syslinux_target_appends "$cfg")"
	if [ -z "$target" ]; then
		warn "No 'MENU LABEL Arch Linux' or 'MENU LABEL Artix" \
			"Linux' entry with an APPEND line found in $cfg;" \
			"add these parameters manually:$kernel_params"
		return 0
	fi
	local missing param
	missing=""
	for param in $kernel_params; do
		if ! line_has_param "$target" "$param"; then
			missing="$missing $param"
		fi
	done
	if [ -z "${missing## }" ]; then
		log "Syslinux parameters already configured."
		return 0
	fi
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would append to $cfg:$missing"
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	backup_existing "/boot/syslinux/syslinux.cfg"
	# Edit only APPEND lines inside the Arch/Artix entry. A sed
	# range ending at a blank line can spill into the next entry
	# when the file does not use blank separators.
	local edited
	edited="$(make_tempfile)"
	awk -v extra="$missing" '
		/^[[:space:]]*MENU LABEL/ {
			if ($0 ~ /(Arch|Artix)([[:space:]]+Linux)?[[:space:]]*$/) {
				in_target = 1
			} else {
				in_target = 0
			}
			print
			next
		}
		in_target && /^[[:space:]]*$/ { in_target = 0 }
		in_target && /^[[:space:]]*APPEND[[:space:]]/ {
			print $0 extra
			next
		}
		{ print }
	' "$cfg" >"$edited"
	local cfg_mode
	cfg_mode="$(stat -c '%a' "$cfg")"
	install -m "$cfg_mode" "$edited" "$cfg"
	rm -f "$edited"
	# Verify that the parameters actually landed instead of
	# reporting a silent no-op.
	local still="" p
	target="$(syslinux_target_appends "$cfg")"
	for p in $missing; do
		line_has_param "$target" "$p" || still="$still $p"
	done
	if [ -n "${still## }" ]; then
		warn "Syslinux Arch/Artix entry could not be updated;" \
			"add these parameters manually:$still"
	else
		log "Updated Syslinux configuration."
		CHANGES=$((CHANGES + 1))
	fi
}

# ---- sysctl ------------------------------------------------------
# sysctl_add_line <key=value>
# Idempotently records a sysctl line for the project sysctl file.
sysctl_add_line() {
	local line="$1"
	local key="${line%%=*}"
	local existing
	for existing in $SYSCTL_LINES; do
		if [ "${existing%%=*}" = "$key" ]; then
			return 0
		fi
	done
	SYSCTL_LINES="$SYSCTL_LINES $line"
}

write_sysctl_file() {
	local content line
	content="# Managed by $PROJECT_NAME. See README.md.
# Applied at boot by your init system's sysctl mechanism."
	for line in $SYSCTL_LINES; do
		content="$content
$line"
	done
	write_file "/$SYSCTL_FILE" "$content"
	if [ "$FILE_CHANGED" = "1" ]; then
		log "sysctl settings take effect after reboot" \
			"(apply now with: sysctl --system)."
	else
		log "Sysctl configuration already correct."
	fi
}

# ---- hostname ----------------------------------------------------
set_hostname() {
	local name="$1"
	# Write /etc/hostname through write_file so the change is
	# journalled and --undo can restore the previous name.
	write_file "/etc/hostname" "$name"
	if [ "$init_system" = "systemd" ] &&
		command -v hostnamectl >/dev/null 2>&1; then
		exec_ok hostnamectl set-hostname "$name" ||
			warn "Failed to apply the hostname now; it will" \
				"take effect after reboot."
	else
		exec_ok sh -c "command -v hostname >/dev/null 2>&1 &&
			hostname '$name' || true"
	fi
}

# ---- features ----------------------------------------------------
feature_update_system() {
	ask update "Update the system (pacman -Syu) before" \
		"hardening?"
	if is_yes "$ANSWER"; then
		exec_ok pacman -Syu --noconfirm ||
			warn "System upgrade failed; continuing anyway."
	else
		warn "Skipping system update. A full system upgrade" \
			"(-Syu) is required before installing packages."
	fi
}

feature_sysctl() {
	ask sysctl "Harden the kernel with sysctl settings?"
	is_yes "$ANSWER" || return 0

	# Standard, low-risk settings. These are either kernel
	# defaults or already set by systemd on Arch; they are
	# valuable on Artix and explicit everywhere.
	sysctl_add_line "kernel.kptr_restrict=1"
	sysctl_add_line "fs.protected_symlinks=1"
	sysctl_add_line "fs.protected_hardlinks=1"
	sysctl_add_line "fs.protected_fifos=2"
	sysctl_add_line "fs.protected_regular=2"
	sysctl_add_line "net.ipv4.conf.all.rp_filter=2"
	sysctl_add_line "net.ipv4.conf.default.rp_filter=2"
	sysctl_add_line "net.ipv4.conf.all.accept_redirects=0"
	sysctl_add_line "net.ipv4.conf.default.accept_redirects=0"
	sysctl_add_line "net.ipv4.conf.all.secure_redirects=0"
	sysctl_add_line "net.ipv4.conf.default.secure_redirects=0"
	sysctl_add_line "net.ipv4.conf.all.send_redirects=0"
	sysctl_add_line "net.ipv4.conf.default.send_redirects=0"
	sysctl_add_line "net.ipv6.conf.all.accept_redirects=0"
	sysctl_add_line "net.ipv6.conf.default.accept_redirects=0"

	ask sysctl-strict "Enable strict sysctl settings" \
		"(perf_event_paranoid=3, ptrace_scope=2," \
		"kexec_load_disabled=1, ldisc_autoload=0, higher" \
		"mmap randomization)? These break some developer" \
		"workflows and non-systemd boots via kexec."
	if is_yes "$ANSWER"; then
		sysctl_add_line "kernel.perf_event_paranoid=3"
		sysctl_add_line "kernel.yama.ptrace_scope=2"
		sysctl_add_line "kernel.kexec_load_disabled=1"
		sysctl_add_line "dev.tty.ldisc_autoload=0"
		if [ "$(uname -m)" = "x86_64" ]; then
			sysctl_add_line "vm.mmap_rnd_bits=32"
			sysctl_add_line "vm.mmap_rnd_compat_bits=16"
		fi
	fi

	write_sysctl_file
}

feature_kernel_params() {
	ask kernel-params "Harden the kernel with boot parameters" \
		"(slab_nomerge, init_on_free=1)?"
	is_yes "$ANSWER" || return 0

	kernel_param_add "slab_nomerge"
	kernel_param_add "init_on_free=1"

	ask kernel-params-strict "Enable strict boot parameters" \
		"(vsyscall=none, lockdown=confidentiality," \
		"module.sig_enforce=1, debugfs=off, oops=panic," \
		"mitigations=auto,nosmt)? These break unsigned" \
		"out-of-tree kernel modules, kernel tracing tools," \
		"and disable SMT with a large performance cost."
	if is_yes "$ANSWER"; then
		kernel_param_add "vsyscall=none"
		kernel_param_add "lockdown=confidentiality"
		kernel_param_add "module.sig_enforce=1"
		kernel_param_add "debugfs=off"
		kernel_param_add "oops=panic"
		kernel_param_add "mitigations=auto,nosmt"
	fi
}

feature_disable_ipv6() {
	ask disable-ipv6 "Disable IPv6 entirely" \
		"(network-policy choice, not general security)?"
	if is_yes "$ANSWER"; then
		kernel_param_add "ipv6.disable=1"
	fi
}

feature_ipv6_privacy() {
	# Temporary (privacy) addresses require IPv6 to stay enabled.
	local param
	for param in $kernel_params; do
		if [ "${param%%=*}" = "ipv6.disable" ]; then
			log "IPv6 is disabled; skipping privacy" \
				"extensions."
			return 0
		fi
	done

	ask ipv6-privacy "Prefer IPv6 temporary (privacy)" \
		"addresses for outgoing connections?"
	is_yes "$ANSWER" || return 0

	# Sysctl is the portable mechanism (the init system applies it
	# at boot). The manager-specific settings keep the preference
	# attached to the connection.
	sysctl_add_line "net.ipv6.conf.all.use_tempaddr=2"
	sysctl_add_line "net.ipv6.conf.default.use_tempaddr=2"
	write_sysctl_file

	case "$network_manager" in
	networkmanager)
		write_file \
			"/etc/NetworkManager/conf.d/90-arch-hardening-ipv6-privacy.conf" \
			"# Managed by $PROJECT_NAME. See README.md.
[connection]
ipv6.ip6-privacy=2"
		;;
	systemd-networkd)
		# A standalone .network file would shadow the real
		# interface configuration (networkd applies only the
		# first match), so add a drop-in to every .network.
		local net base found=""
		for net in /usr/lib/systemd/network/*.network \
			/etc/systemd/network/*.network; do
			[ -e "$net" ] || continue
			base="${net##*/}"
			found="1"
			write_file \
				"/etc/systemd/network/${base}.d/99-arch-hardening-ipv6-privacy.conf" \
				"# Managed by $PROJECT_NAME. See README.md.
[Network]
IPv6PrivacyExtensions=yes"
		done
		if [ -z "$found" ]; then
			warn "No systemd-networkd .network files" \
				"found; set IPv6PrivacyExtensions=yes" \
				"manually."
		fi
		;;
	esac
}

feature_firewall() {
	ask firewall "Install and configure an nftables firewall" \
		"with a default-deny inbound policy?"
	is_yes "$ANSWER" || return 0

	install_pkgs nftables ||
		fatal "Could not install nftables."
	if [ "$init_system" != "systemd" ]; then
		install_pkgs_optional "$(init_service_pkg nftables)"
	fi

	# Never break an active remote SSH session without asking.
	nft_allow_ssh="no"
	if sshd_running; then
		ask firewall-ssh "SSH appears to be active. Allow" \
			"inbound SSH in the firewall?"
		if is_yes "$ANSWER"; then
			nft_allow_ssh="yes"
			nft_ssh_ports="$(sshd_configured_ports)"
			[ -n "$nft_ssh_ports" ] || nft_ssh_ports="22"
			log "Allowing SSH port(s):" \
				"$(printf '%s\n' "$nft_ssh_ports" |
					tr '\n' ' ')"
		fi
	fi

	local rules
	rules="$(nftables_ruleset)"

	# Validate before touching the live configuration.
	if command -v nft >/dev/null 2>&1; then
		local tmp
		tmp="$(make_tempfile)"
		printf '%s\n' "$rules" >"$tmp"
		if ! exec_ok nft -c -f "$tmp"; then
			fatal "Generated nftables ruleset failed" \
				"validation. Nothing was changed."
		fi
		rm -f "$tmp"
	fi

	warn "This ruleset drops forwarded traffic and replaces" \
		"only the '$PROJECT_NAME' nftables table. Rules in" \
		"other tables (Docker, libvirt, podman) that rely on" \
		"forwarding may stop working."
	write_file "/etc/nftables.conf" "$rules"
	if [ "$init_system" = "systemd" ] &&
		systemctl is-active --quiet nftables.service 2>/dev/null; then
		warn "nftables is already active; the new ruleset" \
			"takes effect on the next restart or reboot."
	fi
	svc_enable_now "$(service_name_for nftables)"
}

# Print the ports that sshd is configured to listen on. An empty
# result means the OpenSSH default (22).
sshd_configured_ports() {
	grep -hEi '^[[:space:]]*Port[[:space:]]+' \
		"/etc/ssh/sshd_config" \
		"/etc/ssh/sshd_config.d/"*.conf 2>/dev/null |
		awk '{print $2}' | sort -u || true
}

sshd_running() {
	case "$init_system" in
	systemd)
		systemctl is-active --quiet sshd.service 2>/dev/null ||
			svc_is_enabled sshd.service
		;;
	openrc)
		rc-service sshd status >/dev/null 2>&1 ||
			svc_is_enabled sshd
		;;
	*)
		pgrep -x sshd >/dev/null 2>&1 ||
			svc_is_enabled sshd
		;;
	esac
}

nftables_ruleset() {
	local ssh_line="" p
	if [ "$nft_allow_ssh" = "yes" ]; then
		for p in $nft_ssh_ports; do
			case "$p" in
			'' | *[!0-9]*)
				warn "Ignoring invalid SSH port: $p"
				continue
				;;
			esac
			ssh_line="${ssh_line}		tcp dport ${p} accept
"
		done
	fi
	cat <<EOF
#!/usr/bin/nft -f
# Managed by $PROJECT_NAME. See README.md.
# Remove only this project's table. Flushing the whole ruleset
# would silently delete Docker/libvirt/podman and administrator
# firewall rules.
destroy table inet arch_hardening

table inet arch_hardening {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state invalid drop
		ct state established,related accept
		iif "lo" accept
		ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem } accept
		ip6 nexthdr ipv6-icmp icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report } accept
$ssh_line		counter drop
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
	}
	chain output {
		type filter hook output priority 0; policy accept;
	}
}
EOF
}

feature_time_sync() {
	ask time-sync "Ensure network time synchronization is" \
		"enabled (recommended for package and TLS" \
		"signature validation)?"
	if is_yes "$ANSWER"; then
		if [ "$init_system" = "systemd" ]; then
			if pkg_installed chrony || pkg_installed ntp; then
				warn "Another time daemon is installed;" \
					"systemd-timesyncd may conflict with it."
			fi
			svc_enable_now systemd-timesyncd.service
			log "systemd-timesyncd is now enabled. For" \
				"authenticated NTP (NTS) consider chrony" \
				"(see README)."
		else
			install_pkgs chrony ||
				fatal "Could not install chrony."
			install_pkgs_optional "$(init_service_pkg chrony)"
			svc_enable_now "$(service_name_for chrony)"
		fi
		return 0
	fi

	ask disable-time-sync "Disable network time synchronization" \
		"entirely? Correct time is security-relevant" \
		"(package signatures, TLS, logs). This is a" \
		"privacy trade-off, not a security improvement."
	if is_yes "$ANSWER"; then
		if [ "$init_system" = "systemd" ]; then
			exec_ok timedatectl set-ntp 0 ||
				warn "Failed to disable NTP via timedatectl."
			svc_mask systemd-timesyncd.service
			# Disabling synchronization must not leave
			# another daemon running.
			if pkg_installed chrony; then
				svc_mask chrony.service || true
			fi
			if pkg_installed ntp; then
				svc_mask ntpd.service || true
			fi
		else
			if pkg_installed chrony; then
				svc_mask "$(service_name_for chrony)"
			fi
			svc_mask ntpd || true
		fi
	fi
}

feature_apparmor() {
	ask apparmor "Enable AppArmor (mandatory access control)?"
	is_yes "$ANSWER" || return 0
	apparmor_requested=1

	install_pkgs apparmor || fatal "Could not install apparmor."

	case "$init_system" in
	openrc | s6 | dinit)
		install_pkgs_optional "$(init_service_pkg apparmor)"
		;;
	runit)
		# apparmor-runit ships a stage-1 sysinit script;
		# there is no service to enable.
		install_pkgs_optional apparmor-runit
		;;
	esac

	# AppArmor is compiled into the Arch kernels but not in the
	# default LSM list; it must be added via lsm=.
	local active_lsm
	active_lsm="$(cat "/sys/kernel/security/lsm" 2>/dev/null || true)"
	if printf '%s\n' "$active_lsm" | grep -qw 'apparmor'; then
		log "AppArmor is already active in the running kernel."
	else
		local existing_lsm
		existing_lsm="$(existing_lsm_configuration || true)"
		if [ -n "$existing_lsm" ]; then
			case "$existing_lsm" in
			*apparmor*)
				log "AppArmor is already in an existing lsm=" \
					"configuration."
				;;
			*)
				warn "An lsm= parameter without AppArmor is" \
					"already configured. Not overwriting it." \
					"Add AppArmor manually to lsm=."
				;;
			esac
		else
			kernel_param_add \
				"lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
		fi
	fi

	if [ "$init_system" = "runit" ]; then
		log "AppArmor is enabled by the runit stage-1 script" \
			"installed by apparmor-runit. Reboot to activate."
		return 0
	fi
	svc_enable_now "$(service_name_for apparmor)"
	log "Verify activation after reboot with:" \
		"cat /sys/kernel/security/lsm"
}

existing_lsm_configuration() {
	local out=""
	local dir
	out="$(
		{
			cat "/proc/cmdline" 2>/dev/null || true
			# Unified kernel images and some mkinitcpio
			# setups keep the command line here.
			cat "/etc/kernel/cmdline" 2>/dev/null || true
			# Only inspect the configuration that the
			# detected bootloader actually reads. Stale
			# files for other bootloaders must not suppress
			# or contradict the real change.
			case "$bootloader" in
			grub)
				[ -f "/etc/default/grub" ] &&
					grep -hE \
						'^[[:space:]]*GRUB_CMDLINE_LINUX(_DEFAULT)?=' \
						"/etc/default/grub" || true
				;;
			systemd-boot)
				for dir in "/boot/loader/entries" \
					"/efi/loader/entries" \
					"/boot/efi/loader/entries"; do
					[ -d "$dir" ] || continue
					grep -hE \
						'^[[:space:]]*options([[:space:]]|$)' \
						"$dir"/*.conf 2>/dev/null ||
						true
				done
				;;
			syslinux)
				[ -f "/boot/syslinux/syslinux.cfg" ] &&
					syslinux_target_appends \
						"/boot/syslinux/syslinux.cfg" ||
					true
				;;
			esac
		} | grep -oE 'lsm=[^[:space:]"]*' || true
	)"
	[ -n "$out" ] || return 1
	printf '%s\n' "$out"
}

feature_linux_hardened() {
	ask linux-hardened "Install the linux-hardened kernel" \
		"(keeps your current kernel as a fallback)?"
	is_yes "$ANSWER" || return 0
	linux_hardened_requested=1

	local already_installed=""
	pkg_installed linux-hardened && already_installed="1"

	install_pkgs linux-hardened linux-hardened-headers ||
		fatal "Could not install linux-hardened."

	# The package's mkinitcpio hook regenerates the initramfs,
	# but a bootable kernel must actually exist before we claim
	# success. Check this on every run, including when the package
	# was already present.
	if [ "$DRY_RUN" = "0" ] &&
		[ ! -f "/boot/vmlinuz-linux-hardened" ]; then
		fatal "linux-hardened installed but no kernel image" \
			"was found at /boot/vmlinuz-linux-hardened." \
			"Keep booting your current kernel and" \
			"investigate before rebooting."
	fi

	if [ -n "$already_installed" ] && [ "$DRY_RUN" = "0" ]; then
		log "linux-hardened was already installed;" \
			"bootloader untouched."
		return 0
	fi

	case "$bootloader" in
	grub)
		if [ -f "/boot/grub/grub.cfg" ]; then
			backup_existing "/boot/grub/grub.cfg" || true
		fi
		if ! exec_ok grub-mkconfig -o \
			"/boot/grub/grub.cfg"; then
			if [ -e "/boot/grub/grub.cfg${BACKUP_SUFFIX}" ]; then
				cp -a "/boot/grub/grub.cfg${BACKUP_SUFFIX}" \
					"/boot/grub/grub.cfg" 2>/dev/null ||
					true
			fi
			fatal "Failed to regenerate GRUB configuration." \
				"The previous grub.cfg was restored from" \
				"backup."
		fi
		journal_add "G"
		;;
	systemd-boot)
		if ! exec_ok bootctl update; then
			warn "Failed to refresh the systemd-boot" \
				"entries; run 'bootctl update' manually."
		fi
		warn "bootctl update does not create a boot entry" \
			"for linux-hardened. Add /boot/loader/entries/" \
			"linux-hardened.conf manually (or with your" \
			"kernel-install tooling), pointing at" \
			"/boot/vmlinuz-linux-hardened."
		;;
	syslinux)
		if ! exec_ok extlinux --update "/boot/syslinux"; then
			warn "Failed to refresh the Syslinux bootloader;" \
				"run 'extlinux --update /boot/syslinux' manually."
		fi
		warn "extlinux --update does not create a LABEL for" \
			"linux-hardened. Add a Syslinux entry for" \
			"/boot/vmlinuz-linux-hardened manually."
		;;
	none)
		warn "No supported bootloader detected. Configure a" \
			"boot entry for linux-hardened manually."
		;;
	esac

	log "linux-hardened is installed. Reboot and select it" \
		"from the boot menu. Your previous kernel remains" \
		"available as a fallback."
}

feature_bubblewrap() {
	ask bubblewrap "Install bubblewrap (application sandboxing)?"
	is_yes "$ANSWER" || return 0

	install_pkgs bubblewrap || warn "Could not install bubblewrap."
	if [ "$DRY_RUN" = "0" ] && ! pkg_installed bubblewrap; then
		return 0
	fi

	# linux-hardened disables unprivileged user namespaces, so
	# plain bubblewrap cannot create sandboxes there. During a
	# dry run linux-hardened is only staged, not installed.
	if pkg_installed linux-hardened ||
		[ "$linux_hardened_requested" = "1" ]; then
		warn "linux-hardened disables unprivileged user" \
			"namespaces; bubblewrap needs the setuid fallback."
		ask bubblewrap-suid "Set the setuid bit on" \
			"/usr/bin/bwrap (matches the former" \
			"bubblewrap-suid package)?"
		if is_yes "$ANSWER"; then
			if exec_ok chmod u+s "/usr/bin/bwrap"; then
				journal_add "X	/usr/bin/bwrap"
			else
				warn "Failed to set the setuid bit on" \
					"/usr/bin/bwrap."
			fi
		fi
	fi
}

feature_chaotic_aur() {
	ask chaotic-aur "Add the Chaotic-AUR repository? WARNING:" \
		"this is an UNOFFICIAL third-party binary repository" \
		"that expands the supply-chain trust boundary of" \
		"pacman. Only needed here for hardened_malloc and" \
		"apparmor.d prebuilt packages."
	is_yes "$ANSWER" || return 0

	if [ -f "/etc/pacman.conf" ] &&
		grep -q '^\[chaotic-aur\]' "/etc/pacman.conf"; then
		log "Chaotic-AUR is already configured."
		chaotic_aur_requested=1
		return 0
	fi

	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would import and sign the Chaotic-AUR" \
			"key, install chaotic-keyring/chaotic-mirrorlist," \
			"add [chaotic-aur] to /etc/pacman.conf and run" \
			"pacman -Syu."
		CHANGES=$((CHANGES + 2))
		chaotic_aur_requested=1
		return 0
	fi

	if ! pacman-key --recv-key 3056513887B78AEB \
		--keyserver keyserver.ubuntu.com; then
		error "Failed to import the Chaotic-AUR signing key."
		return 1
	fi
	if ! pacman-key --lsign-key 3056513887B78AEB; then
		error "Failed to locally sign the Chaotic-AUR key."
		return 1
	fi
	if ! pacman -U --noconfirm \
		'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-keyring.pkg.tar.zst' \
		'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-mirrorlist.pkg.tar.zst'; then
		error "Failed to install the Chaotic-AUR keyring and" \
			"mirrorlist."
		return 1
	fi

	backup_existing "/etc/pacman.conf"
	cat >>"/etc/pacman.conf" <<'EOF'

[chaotic-aur]
Include = /etc/pacman.d/chaotic-mirrorlist
EOF
	log "Added Chaotic-AUR to pacman.conf. Running a full" \
		"system upgrade to keep the system in a consistent" \
		"state."
	if ! pacman -Syu --noconfirm; then
		fatal "pacman -Syu failed after adding Chaotic-AUR."
	fi
	chaotic_aur_requested=1
	CHANGES=$((CHANGES + 1))
}

feature_apparmor_profiles() {
	if ! pkg_installed apparmor &&
		[ "$apparmor_requested" != "1" ]; then
		return 0
	fi
	# A manually installed AUR package needs no third-party
	# repository; only require Chaotic-AUR when the package is
	# actually missing.
	if ! pkg_installed apparmor.d-git &&
		[ "$chaotic_aur_requested" != "1" ] &&
		! grep -q '^\[chaotic-aur\]' \
			"/etc/pacman.conf" 2>/dev/null; then
		log "Skipping apparmor.d: requires Chaotic-AUR (or" \
			"install the apparmor.d-git package from the AUR" \
			"yourself)."
		return 0
	fi
	ask apparmor-profiles "Install the apparmor.d profile set" \
		"from Chaotic-AUR (third-party profiles; upstream" \
		"describes the project as not yet stable)?"
	if is_yes "$ANSWER"; then
		install_pkgs_optional apparmor.d-git
		append_line_if_missing \
			"/etc/apparmor/parser.conf" "write-cache"
		append_line_if_missing \
			"/etc/apparmor/parser.conf" "Optimize=compress-fast"
	fi
}

feature_hardened_malloc() {
	ask hardened-malloc "Configure hardened_malloc (advanced," \
		"compatibility-sensitive malloc replacement)?"
	is_yes "$ANSWER" || return 0

	if ! pkg_installed hardened_malloc &&
		[ "$chaotic_aur_requested" != "1" ] &&
		! grep -q '^\[chaotic-aur\]' \
			"/etc/pacman.conf" 2>/dev/null; then
		warn "hardened_malloc is not in the official" \
			"repositories. Build it from the AUR" \
			"(hardened_malloc PKGBUILD) or add Chaotic-AUR." \
			"Skipping."
		return 0
	fi

	install_pkgs hardened_malloc ||
		fatal "Could not install hardened_malloc."

	# hardened_malloc recommends raising vm.max_map_count.
	local mmap_conf="/etc/sysctl.d/99-arch-hardening-malloc.conf"
	write_file "$mmap_conf" \
		"# Managed by $PROJECT_NAME. See README.md.
vm.max_map_count = 1048576"

	ask hardened-malloc-global "Preload hardened_malloc" \
		"globally for ALL programs via /etc/ld.so.preload?" \
		"This breaks some applications (e.g. Electron apps," \
		"games) and costs performance. NOT recommended."
	if is_yes "$ANSWER"; then
		if [ ! -e "/usr/lib/libhardened_malloc.so" ] &&
			[ "$DRY_RUN" = "0" ]; then
			warn "/usr/lib/libhardened_malloc.so does not" \
				"exist; refusing to add it to" \
				"/etc/ld.so.preload."
			return 0
		fi
		append_line_if_missing "/etc/ld.so.preload" \
			"/usr/lib/libhardened_malloc.so"
	else
		log "Using hardened_malloc selectively. Start" \
			"individual applications with:" \
			"LD_PRELOAD=/usr/lib/libhardened_malloc.so <app>"
	fi
}

feature_microcode() {
	ask microcode "Install CPU microcode updates (strongly" \
		"recommended for CPU vulnerability mitigations)?"
	is_yes "$ANSWER" || return 0

	detect_cpu_vendor
	if [ -z "$cpu_vendor" ]; then
		warn "Could not detect the CPU vendor. Skipping" \
			"microcode installation."
		return 0
	fi

	install_pkgs "${cpu_vendor}-ucode" ||
		fatal "Could not install ${cpu_vendor}-ucode."

	# mkinitcpio and dracut embed the microcode into the
	# initramfs automatically; no bootloader changes needed.
	if [ -f "/etc/mkinitcpio.conf" ] &&
		! grep -qE '^HOOKS=.*microcode' \
			"/etc/mkinitcpio.conf"; then
		warn "The 'microcode' hook is missing from" \
			"/etc/mkinitcpio.conf HOOKS. Add it and rebuild" \
			"the initramfs for early loading."
	fi
	log "Microcode will be applied early at boot by the" \
		"generated initramfs (mkinitcpio/dracut)."
}

feature_root_restrictions() {
	ask restrict-su "Restrict su to members of the wheel group?"
	if is_yes "$ANSWER"; then
		# An empty wheel group would lock out su entirely.
		if command -v getent >/dev/null 2>&1; then
			local wheel_members
			wheel_members="$(getent group wheel 2>/dev/null |
				cut -d: -f4 || true)"
			if [ -z "$wheel_members" ]; then
				warn "The wheel group has no listed members." \
					"Add your administrative user to wheel" \
					"before restricting su."
			fi
		fi
		local f wheel_re rootok_re
		wheel_re='^(#[[:space:]]*)(auth[[:space:]]+required'
		wheel_re+='[[:space:]]+pam_wheel[.]so.*)$'
		rootok_re='^[[:space:]]*auth[[:space:]]+sufficient'
		rootok_re+='[[:space:]]+pam_rootok[.]so'
		for f in su su-l; do
			local pam="/etc/pam.d/$f"
			[ -f "$pam" ] || continue
			if grep -qE "$wheel_re" "$pam"; then
				backup_existing "$pam"
				[ "$DRY_RUN" = "1" ] ||
					sed -i -E \
						"s|${wheel_re}|\2|" \
						"$pam"
				log "Enabled pam_wheel in $pam"
				CHANGES=$((CHANGES + 1))
			elif ! grep -q 'pam_wheel[.]so' "$pam"; then
				if ! grep -qE "$rootok_re" "$pam"; then
					warn "No pam_rootok.so line in $pam;" \
						"add pam_wheel.so use_uid manually."
					continue
				fi
				backup_existing "$pam"
				[ "$DRY_RUN" = "1" ] ||
					sed -i -E \
						"/${rootok_re}/a auth		required	pam_wheel.so use_uid" \
						"$pam"
				log "Inserted pam_wheel in $pam"
				CHANGES=$((CHANGES + 1))
			else
				log "pam_wheel already configured in $pam"
			fi
		done
	fi

	ask lock-root "Lock the root account password" \
		"(recover with sudo or another administrative" \
		"account; the locked password cannot be used at" \
		"the console)?"
	if is_yes "$ANSWER"; then
		exec_ok passwd -l root ||
			warn "Failed to lock the root password."
	fi

	if [ -f "/etc/ssh/sshd_config" ]; then
		ask deny-root-ssh "Deny direct root login via SSH" \
			"(drop-in sshd_config.d file)?"
		if is_yes "$ANSWER"; then
			local dropin="/etc/ssh/sshd_config.d/99-arch-hardening.conf"
			if ! grep -qE \
				'^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' \
				"/etc/ssh/sshd_config"; then
				warn "/etc/ssh/sshd_config does not include" \
					"/etc/ssh/sshd_config.d/*.conf; the" \
					"drop-in may be ignored."
			fi
			write_file "$dropin" \
				"# Managed by $PROJECT_NAME. See README.md.
PermitRootLogin no"
			if command -v sshd >/dev/null 2>&1; then
				if ! exec_ok sshd -t; then
					# Do not leave an invalid drop-in in
					# the SSH configuration.
					if [ -e "${dropin}${BACKUP_SUFFIX}" ]; then
						cp -a "${dropin}${BACKUP_SUFFIX}" \
							"$dropin" 2>/dev/null ||
							true
					else
						rm -f "$dropin"
					fi
					fatal "sshd -t rejected the generated" \
						"configuration; the drop-in was" \
						"reverted."
				fi
				if [ "$DRY_RUN" = "0" ]; then
					local effective
					if ! effective="$(sshd -T 2>/dev/null)"; then
						warn "Could not verify the effective" \
							"sshd configuration with sshd -T."
					elif ! printf '%s\n' "$effective" |
						grep -qiE \
							'^permitrootlogin[[:space:]]+no$'; then
						warn "The effective sshd configuration" \
							"still permits root login. Check" \
							"Include order and other" \
							"sshd_config.d/*.conf files."
					fi
				fi
			fi
		fi
	fi
}

feature_umask() {
	ask umask "Set a more restrictive default umask for" \
		"interactive shells?"
	is_yes "$ANSWER" || return 0

	ask_choice umask-value \
		"Choose the umask" 027 077
	local value="$ANSWER"
	write_file "/etc/profile.d/99-arch-hardening-umask.sh" \
		"# Managed by $PROJECT_NAME. See README.md.
umask ${value}"
}

feature_coredumps() {
	ask coredumps "Disable core dump storage (crash" \
		"diagnostics become unavailable)?"
	is_yes "$ANSWER" || return 0

	if [ "$init_system" = "systemd" ]; then
		# Keep systemd-coredump as the handler so crashes
		# are still journaled, but store no core files.
		write_file \
			"/etc/systemd/coredump.conf.d/99-arch-hardening.conf" \
			"# Managed by $PROJECT_NAME. See README.md.
[Coredump]
Storage=none"
	else
		write_file "/etc/sysctl.d/99-arch-hardening-coredumps.conf" \
			"# Managed by $PROJECT_NAME. See README.md.
kernel.core_pattern=|/bin/false"
		if [ -f "/etc/security/limits.conf" ]; then
			append_line_if_missing \
				"/etc/security/limits.conf" "* hard core 0"
		fi
	fi
}

feature_usbguard() {
	ask usbguard "Install USBGuard (USB device authorization)?"
	is_yes "$ANSWER" || return 0

	install_pkgs usbguard || fatal "Could not install usbguard."
	if [ "$init_system" != "systemd" ]; then
		install_pkgs_optional "$(init_service_pkg usbguard)"
	fi

	ask usbguard-policy "Generate an allow policy from the" \
		"currently connected USB devices? Make sure your" \
		"keyboard, mouse and trusted devices are plugged in."
	local has_policy="0"
	if is_yes "$ANSWER"; then
		if [ "$DRY_RUN" = "1" ]; then
			log "Dry-run: usbguard generate-policy" \
				"> /etc/usbguard/rules.conf"
			has_policy="1"
		else
			local rules
			rules="$(usbguard generate-policy 2>/dev/null)" ||
				warn "usbguard generate-policy failed."
			if [ -n "$rules" ]; then
				write_file "/etc/usbguard/rules.conf" "$rules"
				has_policy="1"
			fi
		fi
	else
		# Enabling USBGuard without a policy can block every
		# newly connected device, including the keyboard. Only
		# proceed when a policy already exists.
		if [ -s "/etc/usbguard/rules.conf" ]; then
			log "Using the existing USBGuard policy."
			has_policy="1"
		else
			warn "No policy generated. Generate one later" \
				"with: usbguard generate-policy >" \
				"/etc/usbguard/rules.conf"
		fi
	fi

	if [ "$has_policy" != "1" ]; then
		warn "USBGuard was installed but NOT enabled: without" \
			"a policy all newly connected USB devices," \
			"including keyboards, would be denied. Generate" \
			"a policy, then enable the service manually."
		return 0
	fi

	svc_enable_now "$(service_name_for usbguard)"
}

feature_dma_blacklist() {
	ask dma "Blacklist FireWire kernel modules (DMA-capable" \
		"hardware attack surface)?"
	is_yes "$ANSWER" || return 0

	# The thunderbolt driver is not built in Arch/Artix
	# kernels, so only FireWire modules are relevant.
	local content
	content="# Managed by $PROJECT_NAME. See README.md."
	for mod in firewire-core firewire-ohci; do
		if modinfo -k "$(uname -r)" "$mod" \
			>/dev/null 2>&1; then
			content="$content
install $mod /bin/true"
		fi
	done
	write_file "/$MODPROBE_PREFIX-dma.conf" "$content"
}

feature_webcam_microphone() {
	ask webcam "Blacklist the webcam kernel module" \
		"(uvcvideo)? This is a hardware-disable policy with" \
		"usability consequences."
	if is_yes "$ANSWER"; then
		write_file "/$MODPROBE_PREFIX-webcam.conf" \
			"# Managed by $PROJECT_NAME. See README.md.
install uvcvideo /bin/true"
	fi

	ask microphone "Blacklist the detected audio kernel" \
		"modules (microphone AND speakers)? This breaks all" \
		"analog/HDMI audio driven by those modules."
	if is_yes "$ANSWER"; then
		local content
		content="# Managed by $PROJECT_NAME. See README.md."
		if [ -r "/proc/asound/modules" ]; then
			local mod
			# shellcheck disable=SC2013
			for mod in $(awk '{print $2}' \
				"/proc/asound/modules" |
				awk '!x[$0]++'); do
				content="$content
install $mod /bin/true"
			done
		else
			warn "No /proc/asound/modules found; audio" \
				"drivers may be built into the kernel or" \
				"not loaded. Nothing was blacklisted."
		fi
		write_file "/$MODPROBE_PREFIX-mic.conf" "$content"
	fi
}

feature_wireless() {
	ask rfkill "Block all wireless devices with rfkill now?" \
		"This immediately drops Wi-Fi, WWAN and Bluetooth," \
		"including any remote session carried over them." \
		"It is not reliably persistent across reboots" \
		"(systemd may restore it). Continue?"
	if is_yes "$ANSWER"; then
		exec_ok rfkill block all ||
			warn "rfkill block all failed."
		ask rfkill-wifi "Unblock WiFi again (keep Bluetooth" \
			"blocked)?"
		if is_yes "$ANSWER"; then
			exec_ok rfkill unblock wifi ||
				warn "rfkill unblock wifi failed."
		fi
	fi

	ask bluetooth "Persistently blacklist the Bluetooth" \
		"kernel modules?"
	if is_yes "$ANSWER"; then
		local content
		content="# Managed by $PROJECT_NAME. See README.md."
		for mod in bluetooth btusb; do
			if modinfo -k "$(uname -r)" "$mod" \
				>/dev/null 2>&1; then
				content="$content
install $mod /bin/true"
			fi
		done
		write_file "/$MODPROBE_PREFIX-bluetooth.conf" "$content"
	fi
}

feature_mac_randomization() {
	ask mac "Randomize MAC addresses" \
		"(privacy measure; not a security control)?"
	is_yes "$ANSWER" || return 0

	case "$network_manager" in
	networkmanager)
		ask_choice mac-mode "MAC mode (random or stable)" \
			random stable
		local mode="$ANSWER"
		write_file \
			"/etc/NetworkManager/conf.d/90-arch-hardening-mac.conf" \
			"# Managed by $PROJECT_NAME. See README.md.
[device]
wifi.scan-rand-mac-address=yes
[connection]
wifi.cloned-mac-address=${mode}
ethernet.cloned-mac-address=${mode}"
		;;
	systemd-networkd)
		ask_choice mac-mode \
			"MAC mode (random or persistent)" \
			random persistent
		local mode="$ANSWER"
		write_file "/etc/systemd/network/99-arch-hardening-mac.link" \
			"# Managed by $PROJECT_NAME. See README.md.
[Link]
MACAddressPolicy=${mode}"
		;;
	iwd)
		# Modern iwd already randomizes per-network by
		# default; make it explicit. Insert into [General]
		# when it exists so the key does not land in whatever
		# section happens to be last.
		local iwd_conf="/etc/iwd/main.conf"
		if grep -qx 'AddressRandomization=network' \
			"$iwd_conf" 2>/dev/null; then
			log "iwd already randomizes MAC addresses."
		elif grep -q '^AddressRandomization=' \
			"$iwd_conf" 2>/dev/null; then
			warn "iwd already has an AddressRandomization" \
				"setting; not overwriting it."
		elif grep -qx '\[General\]' "$iwd_conf" 2>/dev/null; then
			backup_existing "$iwd_conf"
			[ "$DRY_RUN" = "1" ] ||
				sed -i \
					'/^\[General\]$/a AddressRandomization=network' \
					"$iwd_conf"
			log "Enabled iwd MAC randomization."
			CHANGES=$((CHANGES + 1))
		else
			append_line_if_missing "$iwd_conf" "[General]"
			append_line_if_missing "$iwd_conf" \
				"AddressRandomization=network"
		fi
		;;
	*)
		log "No supported network manager detected; using" \
			"a macchanger boot service."
		install_pkgs macchanger ||
			fatal "Could not install macchanger."
		install_macchanger_service
		;;
	esac
}

install_macchanger_service() {
	local src
	src="$(dirname "$0")/spoof-mac-addresses.bash"
	if [ ! -r "$src" ]; then
		fatal "spoof-mac-addresses.bash not found next to" \
			"this script."
	fi
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would install /usr/lib/arch-hardening-script/" \
			"and the MAC spoofing service."
		return 0
	fi
	local target="/usr/lib/arch-hardening-script/spoof-mac-addresses"
	local target_content
	target_content="$(cat "$src")"
	# write_file records "C" only for a new file and "M" for a
	# pre-existing administrator file, so reruns are idempotent
	# and --undo can restore the original.
	write_file "$target" "$target_content"
	chmod 0755 "$target" ||
		warn "Failed to make $target executable."

	case "$init_system" in
	systemd)
		write_file "/etc/systemd/system/macspoof.service" \
			"$(macspoof_systemd_unit)"
		svc_enable macspoof.service
		;;
	openrc)
		write_file "/etc/init.d/macspoof" \
			"$(macspoof_openrc_script)"
		chmod 0755 "/etc/init.d/macspoof" ||
			warn "Failed to make /etc/init.d/macspoof" \
				"executable."
		svc_enable macspoof
		;;
	runit)
		write_file "/etc/runit/sv/macspoof/run" \
			"$(macspoof_runit_script)"
		chmod 0755 "/etc/runit/sv/macspoof/run" ||
			warn "Failed to make the runit macspoof" \
				"service executable."
		svc_enable macspoof
		;;
	s6)
		write_file "/etc/s6/adminsv/macspoof/up" \
			"$(macspoof_s6_script)"
		write_file "/etc/s6/adminsv/macspoof/type" "oneshot"
		chmod 0755 "/etc/s6/adminsv/macspoof/up" ||
			warn "Failed to make the s6 macspoof service" \
				"executable."
		svc_enable macspoof
		;;
	dinit)
		write_file "/etc/dinit.d/macspoof" \
			"$(macspoof_dinit_script)"
		svc_enable macspoof
		;;
	esac
}

macspoof_systemd_unit() {
	cat <<'EOF'
# Managed by arch-hardening-script. See README.md.
[Unit]
Description=Spoofs MAC addresses
Wants=network-pre.target
Before=network-pre.target

[Service]
ExecStart=/usr/lib/arch-hardening-script/spoof-mac-addresses
Type=oneshot
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateTmp=true
MemoryDenyWriteExecute=true
NoNewPrivileges=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_NETLINK
SystemCallArchitectures=native
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
EOF
}

macspoof_openrc_script() {
	cat <<'EOF'
#!/sbin/openrc-run
description="Spoof MAC addresses at boot"
depend() { before net; }
start() {
	/usr/lib/arch-hardening-script/spoof-mac-addresses
}
EOF
}

macspoof_runit_script() {
	cat <<'EOF'
#!/bin/bash
set -e
/usr/lib/arch-hardening-script/spoof-mac-addresses
exec sleep infinity
EOF
}

macspoof_s6_script() {
	cat <<'EOF'
#!/usr/bin/execlineb -P
/usr/lib/arch-hardening-script/spoof-mac-addresses
EOF
}

macspoof_dinit_script() {
	cat <<'EOF'
type = scripted
command = /usr/lib/arch-hardening-script/spoof-mac-addresses
before = network.target
EOF
}

feature_hostname() {
	ask hostname "Change the hostname to the generic name" \
		"'host'? A static generic hostname reduces one" \
		"identifier but does not provide anonymity and may" \
		"itself become a stable identifier."
	if is_yes "$ANSWER"; then
		set_hostname host
		warn "/etc/hosts was not modified. Local name" \
			"resolution and some tools may still refer to" \
			"the previous hostname; review /etc/hosts."
	fi

	ask dhcp-hostname "Stop announcing the hostname to" \
		"DHCP servers (where supported)?"
	if is_yes "$ANSWER"; then
		case "$network_manager" in
		networkmanager)
			write_file \
				"/etc/NetworkManager/conf.d/90-arch-hardening-hostname.conf" \
				"# Managed by $PROJECT_NAME. See README.md.
[connection]
hostname.send-hostname=0"
			;;
		systemd-networkd)
			# networkd applies only the first matching
			# .network file, so a standalone catch-all
			# file would shadow the interface's real
			# configuration. Add a [DHCPv4] drop-in to
			# every existing .network file instead.
			local net base found=""
			for net in /usr/lib/systemd/network/*.network \
				/etc/systemd/network/*.network; do
				[ -e "$net" ] || continue
				base="${net##*/}"
				found="1"
				write_file \
					"/etc/systemd/network/${base}.d/99-arch-hardening-hostname.conf" \
					"# Managed by $PROJECT_NAME. See README.md.
[DHCPv4]
SendHostname=no"
			done
			if [ -z "$found" ]; then
				warn "No systemd-networkd .network files" \
					"found; set SendHostname=no in your" \
					"network file manually."
			fi
			;;
		*)
			warn "No supported network manager detected;" \
				"skipping DHCP hostname configuration."
			;;
		esac
	fi
}

feature_tor() {
	ask tor "Install Tor (SOCKS proxy on port 9050)? This" \
		"does NOT route your whole system through Tor."
	is_yes "$ANSWER" || return 0

	install_pkgs tor || fatal "Could not install tor."
	if [ "$init_system" != "systemd" ]; then
		install_pkgs_optional "$(init_service_pkg tor)"
	fi
	svc_enable_now "$(service_name_for tor)"
	log "Tor SOCKS proxy available at 127.0.0.1:9050." \
		"Configure individual applications to use it" \
		"(e.g. torsocks)."

	ask tor-pacman "Route pacman downloads through Tor" \
		"(XferCommand)? Adds latency; package integrity" \
		"remains protected by pacman signatures."
	if is_yes "$ANSWER"; then
		configure_pacman_tor
	fi
}

configure_pacman_tor() {
	local pacman_conf="/etc/pacman.conf"
	[ -f "$pacman_conf" ] || {
		warn "No /etc/pacman.conf found."
		return 0
	}
	if ! command -v curl >/dev/null 2>&1; then
		warn "curl is required for the Tor XferCommand but" \
			"is not installed; not configuring it."
		return 0
	fi
	if grep -q '^XferCommand' "$pacman_conf"; then
		warn "An XferCommand is already configured in" \
			"/etc/pacman.conf. Not overwriting it."
		return 0
	fi
	# XferCommand is an [options] directive. A directive placed
	# outside any section makes pacman fail to parse the file.
	if ! grep -q '^\[options\]' "$pacman_conf"; then
		warn "No [options] section in /etc/pacman.conf;" \
			"not configuring XferCommand."
		return 0
	fi
	local line
	line="XferCommand = /usr/bin/curl --socks5-hostname \
localhost:9050 --continue-at - --fail --output %o %u"
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: would set pacman XferCommand."
		CHANGES=$((CHANGES + 1))
		return 0
	fi
	backup_existing "/etc/pacman.conf"
	sed -i "/^\[options\]/a $line" "$pacman_conf"
	log "Configured pacman to download via Tor (SOCKS" \
		"port 9050). Ensure Tor is running."
	CHANGES=$((CHANGES + 1))
}

feature_uncommon_protocols() {
	ask protocols "Blacklist uncommon network protocol" \
		"modules (defense in depth)?"
	is_yes "$ANSWER" || return 0

	local content
	content="# Managed by $PROJECT_NAME. See README.md."
	local mod skipped=""
	for mod in sctp rds tipc atm n_hdlc af_802154; do
		if modinfo -k "$(uname -r)" "$mod" \
			>/dev/null 2>&1; then
			content="$content
install $mod /bin/true"
		else
			skipped="$skipped $mod"
		fi
	done
	[ -n "$skipped" ] && log "Modules not present in this" \
		"kernel (skipped):$skipped"
	write_file "/$MODPROBE_PREFIX-protocols.conf" "$content"
}

feature_uncommon_filesystems() {
	ask filesystems "Blacklist uncommon filesystem modules" \
		"(defense in depth; mounting them already requires" \
		"privileges)?"
	is_yes "$ANSWER" || return 0

	local content
	content="# Managed by $PROJECT_NAME. See README.md."
	local mod skipped=""
	for mod in cramfs freevxfs jffs2 hfs hfsplus udf; do
		if modinfo -k "$(uname -r)" "$mod" \
			>/dev/null 2>&1; then
			content="$content
install $mod /bin/true"
		else
			skipped="$skipped $mod"
		fi
	done
	[ -n "$skipped" ] && log "Modules not present in this" \
		"kernel (skipped):$skipped"
	write_file "/$MODPROBE_PREFIX-filesystems.conf" "$content"
}

# ---- undo ---------------------------------------------------------
do_undo() {
	if [ ! -f "$JOURNAL" ]; then
		log "Nothing recorded by this script to undo."
		exit 0
	fi

	log "Reverting changes recorded in $JOURNAL"
	local grub_touched=""
	local line
	IN_UNDO=1
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		G) grub_touched="1" ;;
		C?*)
			local created="${line#C	}"
			if [ -e "$created" ]; then
				if [ "$DRY_RUN" = "1" ]; then
					log "Dry-run: would remove $created"
				elif rm -f "$created"; then
					log "Removed: $created"
				else
					warn "Failed to remove $created."
				fi
			fi
			;;
		M?*)
			local target="${line#M	}"
			local backup="${target#*	}"
			target="${target%%	*}"
			if [ -e "$backup" ]; then
				if [ "$DRY_RUN" = "1" ]; then
					log "Dry-run: would restore $target"
				else
					if cp -a "$backup" "$target"; then
						log "Restored: $target"
					else
						warn "Failed to restore $target" \
							"from $backup."
					fi
				fi
			else
				warn "Backup missing for $target; not" \
					"restored."
			fi
			;;
		S+?*)
			local svc="${line#S+	}"
			svc_disable "$svc" || true
			;;
		S-?*)
			local masked="${line#S-	}"
			local prev="${masked#*	}"
			masked="${masked%%	*}"
			# Older journals have only two fields. Only
			# unmask when this script applied the mask,
			# never remove an administrator's pre-existing
			# mask.
			local was_masked="0"
			if [ "$prev" != "${prev#*	}" ]; then
				was_masked="${prev#*	}"
				prev="${prev%%	*}"
			fi
			if [ "$was_masked" != "1" ]; then
				svc_unmask "$masked"
			fi
			if [ "$prev" = "1" ]; then
				svc_enable "$masked" || true
			fi
			;;
		X?*)
			local subid="${line#X	}"
			if [ "$DRY_RUN" = "1" ]; then
				log "Dry-run: would clear the setuid bit" \
					"on $subid"
			else
				chmod u-s "$subid" 2>/dev/null || true
				log "Cleared setuid bit on: $subid"
			fi
			;;
		esac
	done <"$JOURNAL"

	if [ -n "$grub_touched" ] &&
		command -v grub-mkconfig >/dev/null 2>&1 &&
		[ -f "/boot/grub/grub.cfg" ]; then
		if [ "$DRY_RUN" = "1" ]; then
			log "Dry-run: would regenerate the GRUB" \
				"configuration."
		else
			log "Regenerating GRUB configuration."
			grub-mkconfig -o "/boot/grub/grub.cfg" ||
				warn "grub-mkconfig failed during undo."
		fi
	fi

	if [ "$DRY_RUN" = "1" ]; then
		log "Dry-run: the journal was left untouched."
		return 0
	fi
	rm -f "$JOURNAL"
	rmdir "$STATE_DIR" 2>/dev/null || true
	log "Undo complete. Installed packages were left in" \
		"place; remove them manually if desired. Sysctl" \
		"values revert at the next reboot."
}

# ---- main ---------------------------------------------------------
check_root() {
	if [ "$DRY_RUN" = "1" ]; then
		return 0
	fi
	if [ "$(id -u)" -ne 0 ]; then
		fatal "This script must be run as root (sudo)." \
			"Use --dry-run to preview changes without" \
			"root privileges."
	fi
}

print_banner() {
	cat <<EOF

$PROJECT_NAME $VERSION
Arch Linux / Artix Linux hardening script.

This script changes kernel parameters, firewall rules, service
states and system configuration. Review the README and the
changes below carefully. Running this script does not make a
system "secure"; it implements selected hardening and privacy
measures whose trade-offs you are asked to confirm.

EOF
}

summarize() {
	log "Summary:"
	log "  Init system:    $init_system"
	log "  Distribution:   ${distro_id:-unknown}"
	log "  Bootloader:     $bootloader"
	log "  Changes made:   $CHANGES"
	if [ "$DRY_RUN" = "1" ]; then
		log "Dry run: nothing was modified."
	elif [ "$CHANGES" -gt 0 ]; then
		log "Most kernel-level changes take effect after a" \
			"reboot."
	fi
}

ending() {
	ask reboot "Reboot now to apply all changes?"
	if is_yes "$ANSWER"; then
		exec_ok reboot ||
			warn "Reboot failed; please reboot manually."
	fi
}

main() {
	parse_arguments "$@"
	load_config_file

	if [ "$DO_UNDO" = "1" ]; then
		check_root
		detect_init
		do_undo
		exit 0
	fi

	check_root
	print_banner
	detect_distro
	detect_init
	detect_bootloader
	detect_network_manager
	detect_cpu_vendor

	feature_update_system
	feature_sysctl
	feature_kernel_params
	feature_disable_ipv6
	feature_ipv6_privacy
	feature_firewall
	feature_time_sync
	feature_apparmor
	feature_linux_hardened
	feature_bubblewrap
	# Chaotic-AUR is optional and may fail independently (network,
	# key server). Do not abort the remaining measures.
	feature_chaotic_aur ||
		warn "Chaotic-AUR setup failed; continuing without it."
	feature_apparmor_profiles
	feature_hardened_malloc
	feature_microcode
	feature_root_restrictions
	feature_umask
	feature_coredumps
	feature_usbguard
	feature_dma_blacklist
	feature_webcam_microphone
	feature_wireless
	feature_mac_randomization
	feature_hostname
	feature_tor
	feature_uncommon_protocols
	feature_uncommon_filesystems

	apply_kernel_params
	summarize
	ending
}

main "$@"
