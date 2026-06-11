#!/bin/bash

set -euo pipefail

if [[ -t 1 && ${NO_COLOR:-} != "1" ]]; then
	GREEN="\033[32m"
	YELLOW="\033[33m"
	RED="\033[31m"
	RESET="\033[0m"
else
	GREEN=""
	YELLOW=""
	RED=""
	RESET=""
fi

log() { printf '%s %b[INFO]%b ✅ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$GREEN" "$RESET" "$*"; }
warn() { printf '%s %b[WARN]%b ⚠️ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$YELLOW" "$RESET" "$*" >&2; }
error() { printf '%s %b[ERROR]%b ❌ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$RED" "$RESET" "$*" >&2; }

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
	# Get list of network interfaces. Excludes loopback and virtual machine interfaces.
	# Use a safe glob/for loop instead of `ls | grep` to handle arbitrary interface names.
	for p in /sys/class/net/*; do
		[ -e "$p" ] || continue
		iface=${p##*/}
		case "$iface" in
		lo | tun0 | virbr* | docker* | veth*)
			continue
			;;
		esac

		# Spoof the MAC address of the interface.
		ip link set dev "$iface" down
		macchanger -e "$iface" >/dev/null || warn "macchanger failed on $iface"
		ip link set dev "$iface" up
	done
}

main() {
	spoof_mac_addresses
}

main "$@"
