# Arch Hardening Script

## Overview

This script enhances the privacy and security of Arch Linux. Any contribution is highly appreciated.

**WARNING:** It is highly recommended to read and understand the guide before running this script. Do not execute commands you do not understand, as this may lead to unexpected errors. This script alone is not sufficient for complete security. Security requires ongoing efforts such as maintaining AppArmor profiles and practicing good security habits.

## Features

- Harden the kernel using sysctl and boot parameters.
- Disable IPv6 to reduce the attack surface.
- Disable the potentially dangerous Netfilter automatic conntrack helper assignment.
- Install `linux-hardened`.
- Enable AppArmor.
- Add the Chaotic-AUR repository.
- Install AppArmor profiles.
- Install Bubblewrap.
- Install Bubblejail.
- Install and configure `hardened_malloc` for improved memory safety.
- Restrict root access.
- Install and configure UFW as a firewall.
- Set up Tor.
- Change the hostname to a generic one such as `host`.
- Block all wireless devices with `rfkill` and blacklist the Bluetooth kernel modules.
- Create a systemd service to spoof the MAC address at boot.
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

All features are optional, and you will be prompted to enable or disable each one during the script execution.

This script is compatible with Arch Linux using GRUB, systemd-boot, or Syslinux as the bootloader and systemd as the init system. To disable any checks, run the script with the `--disable-checks` flag.

## Usage

1. Clone or download this repository:

    ```sh
    git clone https://github.com/daviduhden/arch-hardening-script.git
    cd arch-hardening-script
    ```

2. Make the script executable:
    ```sh
    chmod +x hardening.ksh
    ```

3. Run the script:

    ```sh
    bash hardening.bash
    ```

4. Follow the interactive prompts to apply the desired configurations.