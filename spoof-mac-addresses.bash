#!/bin/bash

if [[ -z "${ZSH_VERSION:-}" ]] && command -v zsh >/dev/null 2>&1; then
  exec zsh "$0" "$@"
fi

set -euo pipefail

if [[ -t 1 && "${NO_COLOR:-}" != "1" ]]; then
  GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
else
  GREEN=""; YELLOW=""; RED=""; RESET=""
fi

log()   { printf '%s %b[INFO]%b ✅ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s %b[WARN]%b ⚠️ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$YELLOW" "$RESET" "$*" >&2; }
error() { printf '%s %b[ERROR]%b ❌ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$RED" "$RESET" "$*" >&2; }

# MAC addresses spoofing script for Linux
# Copyright (C) 2019 madaidan
# Copyright (C) 2025 David Uhden Collado
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
  interfaces=$(ls /sys/class/net | grep -v 'lo' | grep -v 'tun0' | grep -v "virbr" | grep -v "docker" | grep -v "veth")

  # Spoof the MAC address of each.
  for i in ${interfaces}; do
    ip link set dev "$i" down
    macchanger -e "$i" >/dev/null || warn "macchanger failed on $i"
    ip link set dev "$i" up
  done
}

main() {
  spoof_mac_addresses
}

main "$@"
