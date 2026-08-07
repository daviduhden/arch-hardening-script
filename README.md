# Arch / Artix Hardening Script

## Overview

This script enhances the privacy and security of Arch Linux and Artix Linux. Any contribution is highly appreciated.

**WARNING:** It is highly recommended to read and understand the guide before running this script. Do not execute commands you do not understand, as this may lead to unexpected errors. This script alone is not sufficient for complete security. Security requires ongoing efforts such as maintaining AppArmor profiles and practicing good security habits.

## Features

- Harden the kernel using sysctl and boot parameters.
- Optionally disable IPv6 to reduce the attack surface.
- Disable the potentially dangerous Netfilter automatic conntrack helper assignment.
- Install `linux-hardened`.
- Enable AppArmor.
- Add the Chaotic-AUR repository.
- Install AppArmor profiles.
- Install Bubblewrap.
- Install Bubblejail.
- Install and configure `hardened_malloc` for improved memory safety.
- Restrict root access.
- Install and configure nftables as a firewall with a default-deny inbound policy.
- Set up Tor.
- Change the hostname to a generic one such as `host`.
- Block all wireless devices with `rfkill` and blacklist the Bluetooth kernel modules.
- Create an init service to spoof the MAC address at boot (systemd or OpenRC).
- Use a more restrictive umask.
- Install usbguard to blacklist USB devices.
- Blacklist Thunderbolt and Firewire to prevent DMA attacks.
- Disable coredumps.
- Enable microcode updates.
- Disable NTP.
- Enable IPv6 privacy extensions if IPv6 is not disabled.
- Blacklist uncommon network protocols.
- Blacklist uncommon filesystems.
- Install `haveged` and `jitterentropy` to gather more entropy.
- Blacklist the webcam, microphone, and speaker kernel modules to prevent spying.

All features are optional, and you will be asked to enable or disable each one during the script execution.

## Compatibility

| Component     | Supported                                      |
|---------------|------------------------------------------------|
| Distribution  | Arch Linux, Artix Linux                        |
| Bootloader    | GRUB, systemd-boot, Syslinux                   |
| Init system   | systemd, OpenRC, runit, s6, dinit              |

**Note:** systemd-boot requires systemd as the init system. On non-systemd setups with systemd-boot detected, bootloader features will be limited and a warning is shown.

## Usage

### Quick Start

```sh
git clone https://github.com/daviduhden/arch-hardening-script.git
cd arch-hardening-script
chmod +x hardening.bash
sudo bash hardening.bash
```

### Options

| Flag                | Description                                      |
|---------------------|--------------------------------------------------|
| `--help`, `-h`      | Show the help message.                           |
| `--disable-checks`  | Skip system compatibility checks. Only for       |
|                     | advanced users who know what they are doing.     |

### Interactive Prompts

Each hardening measure requires a `(y/n)` confirmation. Answer `y` to apply, `n` to skip, or `Ctrl-C` to abort the script. You will be asked to reboot at the end to apply all changes.
