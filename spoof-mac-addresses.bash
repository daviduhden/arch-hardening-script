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

# Function to spoof MAC addresses
spoof_mac_addresses() {
	# Get list of network interfaces.
	# Excludes loopback and virtual machine interfaces.
	# Use a safe glob/for loop instead of `ls | grep`
	# to handle arbitrary interface names.
	for p in /sys/class/net/*; do
		[ -e "$p" ] || continue
		iface=${p##*/}
		# Skip loopback, tunnels and virtual/bridge
		# interfaces that have no (or a shared) hardware
		# address to randomize.
		case "$iface" in
		lo | tun* | tap* | virbr* | docker* | veth* | \
			br-* | bond* | dummy* | wg* | vmnet*)
			continue
			;;
		esac

		# A device must be down while its address is changed.
		if ! ip link set dev "$iface" down; then
			warn "could not bring $iface down; skipping"
			continue
		fi
		macchanger -e "$iface" >/dev/null ||
			warn "macchanger failed on $iface"
		ip link set dev "$iface" up ||
			warn "could not bring $iface up"
	done
}

main() {
	spoof_mac_addresses
}

main "$@"
