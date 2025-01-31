#!/bin/bash

#    MAC addresses spoofing script for Linux
#    Copyright (C) 2019 madaidan
#    Copyright (C) 2025 David Uhden Collado
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Get list of network interfaces. Excludes loopback and virtual machine interfaces.
interfaces=$(ls /sys/class/net | grep -v 'lo' | grep -v 'tun0' | grep -v "virbr")

# Spoof the MAC address of each.
for i in ${interfaces}
do
  macchanger -e $i >/dev/null # Hide the output so it can't be discovered with systemd logs.
done