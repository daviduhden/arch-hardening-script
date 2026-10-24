#!/bin/bash

set -euo pipefail

log() { printf \
	'%s [INFO] %s\n' \
	"$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf \
	'%s [WARN] %s\n' \
	"$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
error() { printf \
	'%s [ERROR] %s\n' \
	"$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

# MAC addresses spoofing script for Linux
# Copyright (C) 2019 madaidan
# Copyright (C) 2025-2026 David Uhden Collado
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Interfaces this script brought down, restored by the EXIT trap
# if the process is interrupted.
DOWN_IFACES=""

cleanup() {
	local iface
	for iface in $DOWN_IFACES; do
		ip link set dev "$iface" up 2>/dev/null || true
	done
}
trap cleanup EXIT

# Function to spoof MAC addresses
spoof_mac_addresses() {
	local failures=0 iface p
	# Get list of network interfaces. Only physical devices are
	# touched: /sys/class/net/*/device is absent for bridges,
	# bonds, VLANs, veth pairs, tunnels and other virtual links.
	# Bond/bridge slaves are skipped through master/brport.
	for p in /sys/class/net/*; do
		[ -e "$p" ] || continue
		iface=${p##*/}
		case "$iface" in
		lo | tun* | tap* | virbr* | docker* | veth* | \
			br-* | bond* | dummy* | wg* | vmnet*)
			continue
			;;
		esac
		[ -e "/sys/class/net/$iface/device" ] || continue
		if [ -e "/sys/class/net/$iface/master" ] ||
			[ -e "/sys/class/net/$iface/brport" ]; then
			continue
		fi
		# ARPHRD_ETHER (1) covers Ethernet and Wi-Fi; skip CAN,
		# PPP, tunnels and other non-Ethernet link types.
		local iface_type=""
		read -r iface_type \
			<"/sys/class/net/$iface/type" 2>/dev/null || continue
		[ "$iface_type" = "1" ] || continue
		# Interfaces without a MAC address (e.g. some WWAN
		# links) cannot be spoofed.
		[ -s "/sys/class/net/$iface/address" ] || continue

		# A device must be down while its address is changed.
		if ! ip link set dev "$iface" down; then
			warn "could not bring $iface down; skipping"
			failures=$((failures + 1))
			continue
		fi
		DOWN_IFACES="$DOWN_IFACES $iface"
		# -A randomizes both the vendor OUI and the device
		# bytes. (-e would keep the manufacturer prefix, which
		# weakens the privacy goal of this measure.)
		if ! macchanger -A "$iface" >/dev/null; then
			warn "macchanger failed on $iface"
			failures=$((failures + 1))
		else
			log "spoofed MAC address on $iface"
		fi
		if ! ip link set dev "$iface" up; then
			warn "could not bring $iface up"
			failures=$((failures + 1))
		fi
	done
	[ "$failures" -eq 0 ]
}

main() {
	if [ "$(id -u)" -ne 0 ]; then
		error "must be run as root"
		exit 1
	fi
	if ! command -v ip >/dev/null 2>&1; then
		error "ip (iproute2) is required"
		exit 1
	fi
	if ! command -v macchanger >/dev/null 2>&1; then
		error "macchanger is required"
		exit 1
	fi
	spoof_mac_addresses
}

main "$@"
