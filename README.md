# Arch Hardening Script

This script enhances the privacy and security of Arch Linux.

**WARNING:** It is highly recommended to read and understand the guide before running this script. Do not execute commands you do not understand, as this may lead to unexpected errors. This script alone is not sufficient for complete security. Security requires ongoing efforts such as maintaining AppArmor profiles and practicing good security habits.

## Features

* Kernel hardening via sysctl and boot parameters.
* Disables IPv6 to reduce attack surface.
* Disables the potentially dangerous Netfilter automatic conntrack helper assignment to reduce attack surface.
* Installs `linux-hardened`.
* Enables AppArmor.
* Adds the Chaotic-AUR repository.
* Installs AppArmor profiles.
* Installs Bubblewrap.
* Installs Bubblejail.
* Installs and configures `hardened_malloc` for improved memory safety.
* Restricts root access.
* Installs and configures UFW as a firewall.
* Sets up Tor.
* Changes your hostname to a generic one such as `host`.
* Blocks all wireless devices with `rfkill` and blacklists the Bluetooth kernel modules.
* Creates a systemd service to spoof your MAC address at boot.
* Uses a more restrictive umask.
* Installs usbguard to blacklist USB devices.
* Blacklists Thunderbolt and Firewire to prevent some DMA attacks.
* Disables coredumps.
* Enables microcode updates.
* Disables NTP.
* Enables IPv6 privacy extensions if IPv6 has not been disabled.
* Blacklists uncommon network protocols.
* Blacklists uncommon filesystems.
* Installs `haveged` and `jitterentropy` to gather more entropy.
* Blacklists the webcam, microphone, and speaker kernel modules to prevent spying.

All features are optional, and you will be prompted to enable or disable each one.

This script is compatible with Arch Linux using GRUB, systemd-boot, or Syslinux as the bootloader and systemd as the init system. To disable any checks, run the script with the `--disable-checks` flag.

## Usage

1. Clone or download this repository:

    ```sh
    git clone https://github.com/daviduhden/arch-hardening-script.git
    cd arch-hardening-script
    ```

2. Run the script:

    ```sh
    bash hardening.bash
    ```

    or

    ```sh
    chmod +x hardening.bash && ./hardening.bash
    ```
