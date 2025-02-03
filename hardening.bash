#!/bin/bash -e

# Hardening Script for Arch Linux
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

while test $# -gt 0; do
  case "$1" in
    --disable-checks)
      # Disable script_checks.
      disable_checks=1
      exit 1
      ;;
    *)
      echo "'${*}' is not a correct flag."
      exit 1
      ;;
  esac
done

update_system() {
  echo "Updating the system..."
  pacman -Syu --noconfirm
}

create_grub_directory() {
  # Create /etc/default/grub.d if it doesn't already exist.
  if ! [ -d /etc/default/grub.d ]; then
    mkdir -m 755 /etc/default/grub.d

    # Make /etc/default/grub source grub.d.
    # shellcheck disable=SC2016
    echo '
for i in /etc/default/grub.d/*.cfg ; do
if [ -e "${i}" ]; then
  . "${i}"
fi
done
' >> /etc/default/grub
  fi
}

syslinux_append() {
  new_boot_parameters="$1"

  # Get list of current boot parameters.
  syslinux_parameters=$(grep -v "Fallback" /boot/syslinux/syslinux.cfg | grep -C 2 "MENU LABEL Arch Linux" | grep "APPEND")

  # Add new boot parameters.
  sed -i "s|${syslinux_parameters}|${syslinux_parameters} ${new_boot_parameters}|" /boot/syslinux/syslinux.cfg
}

systemd_boot_append() {
  new_boot_parameters="$1"

  # Append new boot parameters for systemd-boot.
  bootctl update
  sed -i "s|^options .*|& ${new_boot_parameters}|" /boot/loader/entries/*.conf
}

script_checks() {
  if [ "${disable_checks}" != "1" ]; then
    # Check for root
    if [[ "$(id -u)" -ne 0 ]]; then
      echo "This script needs to be run as root."
      exit 1
    fi

    # Check if on Arch Linux.
    if ! grep "Arch Linux" /etc/os-release &>/dev/null; then
      echo "This script can only be used on Arch Linux."
      exit 1
    fi

    # Check which bootloader is being used.
    if [ -d /boot/grub ]; then
      use_grub="y"
      # Create /etc/default/grub.d if it doesn't already exist.
      create_grub_directory
    elif [ -d /boot/syslinux ]; then
      use_syslinux="y"

      if ! grep "MENU LABEL Arch Linux" /boot/syslinux/syslinux.cfg >/dev/null; then
        echo "The 'Arch Linux' menu label is missing from your Syslinux configuration file."
        exit 1
      fi
    elif [ -d /boot/loader ]; then
      use_systemd_boot="y"
    else
      echo "This script can only be used with GRUB, syslinux, or systemd-boot."
      exit 1
    fi

    # Check if using systemd.
    # shellcheck disable=SC2009
    if ! ps -p 1 | grep systemd &>/dev/null; then
      echo "This script can only be used with systemd."
      exit 1
    fi
  fi
}

sysctl_hardening() {
  ## Sysctl
  read -r -p "Harden the kernel with sysctl? (y/n) " sysctl
  if [ "${sysctl}" = "y" ]; then
    # Hide kernel symbols in /proc/kallsyms.
    echo "kernel.kptr_restrict=2" > /etc/sysctl.d/kptr_restrict.conf

    # Restrict dmesg to root.
    echo "kernel.dmesg_restrict=1" > /etc/sysctl.d/dmesg_restrict.conf

    # Prevent kernel log from being displayed in the console during boot.
    echo "kernel.printk=3 3 3 3" > /etc/sysctl.d/printk.conf

    # Harden BPF JIT compiler.
    echo "kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2" > /etc/sysctl.d/harden_bpf.conf

    # Restrict loading TTY line disciplines.
    echo "dev.tty.ldisc_autoload=0" > /etc/sysctl.d/ldisc_autoload.conf

    # Restrict userfaultfd syscall.
    echo "vm.unprivileged_userfaultfd=0" > /etc/sysctl.d/userfaultfd.conf

    # Disable kexec.
    echo "kernel.kexec_load_disabled=1" > /etc/sysctl.d/kexec.conf

    # Disable the SysRq key.
    echo "kernel.sysrq=4" > /etc/sysctl.d/sysrq.conf

    # Disable unprivileged user namespaces.
    echo "kernel.unprivileged_userns_clone=0" > /etc/sysctl.d/unprivileged_userns.conf

    # Restrict performance events.
    echo "kernel.perf_event_paranoid=3" > /etc/sysctl.d/perf_event.conf

    # Harden the TCP/IP stack.
    echo "net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0" > /etc/sysctl.d/tcp_hardening.conf

    # Restrict ptrace to root.
    echo "kernel.yama.ptrace_scope=2" > /etc/sysctl.d/ptrace_scope.conf

    # Improve ASLR for mmap.
    echo "vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16" > /etc/sysctl.d/mmap_aslr.conf

    # Protect symlinks and hardlinks.
    echo "fs.protected_symlinks=1
fs.protected_hardlinks=1" > /etc/sysctl.d/protected_links.conf

    # Protect FIFOs and regular files.
    echo "fs.protected_fifos=2
fs.protected_regular=2" > /etc/sysctl.d/protected_files.conf
  fi
}

boot_parameter_hardening() {
  ## Boot Parameters.
  read -r -p "Harden the kernel through boot parameters? (y/n) " bootparams
  if [ "${bootparams}" = "y" ]; then
    # Define the boot parameters.
    kernel_params="slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt mmio_stale_data=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force"

    # Add ipv6.disable=1 if not using IPv6.
    read -r -p "Disable IPv6? (y/n) " disable_ipv6
    if [ "${disable_ipv6}" = "y" ]; then
      kernel_params="${kernel_params} ipv6.disable=1"
    fi

    # GRUB-specific configuration.
    if [ "${use_grub}" = "y" ]; then
      # Add kernel hardening boot parameters.
      # shellcheck disable=SC2016
      echo "GRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX ${kernel_params}\"" > /etc/default/grub.d/40_kernel_hardening.cfg
      # Regenerate GRUB configuration file.
      grub-mkconfig -o /boot/grub/grub.cfg
    elif [ "${use_syslinux}" = "y" ]; then
      # Append new boot parameters.
      syslinux_append "${kernel_params}"
    elif [ "${use_systemd_boot}" = "y" ]; then
      # Append new boot parameters for systemd-boot.
      bootctl update
      sed -i "s|^options .*|& ${kernel_params}|" /boot/loader/entries/*.conf
    fi
  fi
}

disable_nf_conntrack_helper() {
  ## Disable Netfilter connection tracking helper.
  read -r -p "Disable the Netfilter automatic conntrack helper assignment? (y/n) " disable_conntrack_helper
  if [ "${disable_conntrack_helper}" = "y" ]; then
    echo "options nf_conntrack nf_conntrack_helper=0" > /etc/modprobe.d/no-conntrack-helper.conf
  fi
}

install_linux_hardened() {
  ## Linux-Hardened
  read -r -p "Install linux-hardened? (y/n) " linux_hardened
  if [ "${linux_hardened}" = "y" ]; then
    # Install linux-hardened.
    pacman -S --noconfirm -q linux-hardened linux-hardened-headers

    # Re-generate GRUB configuration.
    grub-mkconfig -o /boot/grub/grub.cfg
  fi
}

apparmor() {
  ## Apparmor
  read -r -p "Enable apparmor? (y/n) " enable_apparmor
  if [ "${enable_apparmor}" = "y" ]; then
    # Check if apparmor is installed and if not, install it
    if ! pacman -Qq apparmor &>/dev/null; then
      pacman -S --noconfirm -q apparmor
    fi

    # Enable AppArmor systemd service.
    systemctl enable apparmor.service

    # Enable AppArmor with a boot parameter.
    if [ "${use_grub}" = "y" ]; then
      # shellcheck disable=SC2016
      echo '''GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX apparmor=1 security=apparmor audit=1"''' > /etc/default/grub.d/40_enable_apparmor.cfg

      # Re-generate GRUB configuration.
      grub-mkconfig -o /boot/grub/grub.cfg
    elif [ "${use_syslinux}" = "y" ]; then
      syslinux_append "apparmor=1 security=apparmor audit=1"
    elif [ "${use_systemd_boot}" = "y" ]; then
      systemd_boot_append "apparmor=1 security=apparmor audit=1"
    fi
  fi
}

add_chaotic_aur() {
  ## Add the Chaotic-AUR repository
  read -r -p "Add the Chaotic-AUR repository? (y/n) " add_chaotic_aur
  if [ "${add_chaotic_aur}" = "y" ]; then
    pacman-key --recv-key 3056513887B78AEB --keyserver keyserver.ubuntu.com
    pacman-key --lsign-key 3056513887B78AEB
    pacman -U --noconfirm 'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-keyring.pkg.tar.zst'
    pacman -U --noconfirm 'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-mirrorlist.pkg.tar.zst'
    echo -e "\n[chaotic-aur]\nInclude = /etc/pacman.d/chaotic-mirrorlist" | tee -a /etc/pacman.conf
    pacman -Syu --noconfirm
  fi
}

install_apparmor_d() {
  ## Install apparmor.d from Chaotic-AUR.
  if pacman -Qq apparmor &>/dev/null && grep -q "\[chaotic-aur\]" /etc/pacman.conf; then
    read -r -p "Install apparmor.d (AppArmor profiles) from Chaotic-AUR? (y/n) " install_apparmor_d
    if [ "${install_apparmor_d}" = "y" ]; then
      pacman -S --noconfirm -q apparmor.d-git

      # Enable fast caching compression of AppArmor profiles.
      echo 'write-cache' | tee -a /etc/apparmor/parser.conf
      echo 'Optimize=compress-fast' | tee -a /etc/apparmor/parser.conf
    fi
  fi
}

get_bubblewrap() {
  ## Bubblewrap
  read -r -p "Install bubblewrap? (y/n) " install_bubblewrap
  if [ "${install_bubblewrap}" = "y" ]; then
    # Installs bubblewrap if it isn't already.
    if ! pacman -Qq bubblewrap &>/dev/null; then
      pacman -S --noconfirm -q bubblewrap
    fi
  fi
}

install_bubblejail() {
  ## Install apparmor.d from Chaotic-AUR.
  if pacman -Qq bubblewrap &>/dev/null && grep -q "\[chaotic-aur\]" /etc/pacman.conf; then
    read -r -p "Install bubblejail from Chaotic-AUR? (y/n) " install_bubblejail
    if [ "${install_bubblejail}" = "y" ]; then
      pacman -S --noconfirm -q bubblejail
    fi
  fi
}

restrict_root() {
  ## Restricting root
  # Clear /etc/securetty
  read -r -p "Clear /etc/securetty? (y/n) " securetty
  if [ "${securetty}" = "y" ]; then
    echo "" > /etc/securetty
  fi

  # Restricting su to users in the wheel group.
  read -r -p "Restrict su to users in the wheel group? (y/n) " restrict_su
  if [ "${restrict_su}" = "y" ]; then
    # Restricts su by editing files in /etc/pam.d/
    sed -i 's/#auth		required	pam_wheel.so use_uid/auth		required	pam_wheel.so use_uid/' /etc/pam.d/su
    sed -i 's/#auth		required	pam_wheel.so use_uid/auth		required	pam_wheel.so use_uid/' /etc/pam.d/su-l
  fi

  # Lock the root account.
  read -r -p "Lock the root account? (y/n) " lock_root_account
  if [ "${lock_root_account}" = "y" ]; then
    passwd -l root
  fi

  # Checks if SSH is installed before asking.
  if [ -x "$(command -v ssh)" ]; then
    # Deny root login via SSH.
    read -r -p "Deny root login via SSH? (y/n) " deny_root_ssh
    if [ "${deny_root_ssh}" = "y" ]; then
      echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
    fi
  fi
}

firewall() {
  ## Firewall
  read -r -p "Install and configure UFW? (y/n) " install_ufw
  if [ "${install_ufw}" = "y" ]; then
    # Installs ufw if it isn't already.
    if ! pacman -Qq ufw &>/dev/null; then
      pacman -S --noconfirm -q ufw
    fi

    # Enable UFW.
    ufw enable
    systemctl enable ufw.service

    # Deny all incoming traffic.
    ufw default deny incoming # Also disables ICMP timestamps
  fi
}

setup_tor() {
  ## Tor.
  read -r -p "Do you want to install Tor? (y/n) " install_tor
  if [ "${install_tor}" = "y" ]; then
    # Installs Tor if it isn't already.
    if ! pacman -Qq tor &>/dev/null; then
      pacman -S --noconfirm -q tor
    fi

    # Force Pacman through Tor
    read -r -p "Force pacman through Tor? (y/n) " pacman_tor
    if [ "${pacman_tor}" = "y" ]; then
      # Configure a SocksPort for Pacman.
      echo '''
# Pacman SocksPort
SocksPort 9062''' >> /etc/tor/torrc
      sed -i 's/#XferCommand = \/usr\/bin\/curl -L -C - -f -o %o %u/XferCommand = \/usr\/bin\/curl --socks5-hostname localhost:9062 --continue-at - --fail --output %o %u/' /etc/pacman.conf

      # Only use https mirrors incase of compromised exit nodes.
      sed -i 's/Server = http:/#Server = http:/' /etc/pacman.d/mirrorlist
    fi

    # Enables tor systemd service.
    systemctl enable --now tor.service
  fi
}

configure_hostname() {
  ## Change hostname to a generic one.
  read -r -p "Change hostname to 'host'? (y/n) " hostname
  if [ "${hostname}" = "y" ]; then
    hostnamectl set-hostname host
  fi
}

block_wireless_devices() {
  ## Wireless devices
  read -r -p "Block all wireless devices with rfkill? (y/n) " block_wireless
  if [ "${block_wireless}" = "y" ]; then
    # Uses rfkill to block all wireless devices.
    rfkill block all

    # Unblock WiFi.
    read -r -p "Unblock WiFi? (y/n) " unblock_wifi
    if [ "${unblock_wifi}" = "y" ]; then
      rfkill unblock wifi
    fi

    # Blacklist bluetooth kernel module.
    read -r -p "Blacklist the bluetooth kernel module? (y/n) " blacklist_bluetooth
    if [ "${blacklist_bluetooth}" = "y" ]; then
      echo "install btusb /bin/true
install bluetooth /bin/true" > /etc/modprobe.d/blacklist-bluetooth.conf
    fi
  fi
}

mac_address_spoofing() {
  ## MAC Address Spoofing.
  read -r -p "Spoof MAC address automatically at boot? (y/n) " spoof_mac_address
  if [ "${spoof_mac_address}" = "y" ]; then
    read -r -p "Use macchanger or NetworkManager? " which_mac_spoofer
    if [ "${which_mac_spoofer}" = "macchanger" ]; then
      # Installs macchanger if it isn't already.
      if ! pacman -Qq macchanger &>/dev/null; then
        pacman -S --noconfirm -q macchanger
      fi

      # Get mac spoofing script.
      mkdir -m 755 /usr/lib/arch-hardening-script
      cp "$(dirname "$0")/spoof-mac-addresses.sh" /usr/lib/arch-hardening-script/spoof-mac-addresses

      # Set permissions.
      chown root -R /usr/lib/arch-hardening-script
      chmod 744 /usr/lib/arch-hardening-script/spoof-mac-addresses

      # Creates systemd service for MAC spoofing.
      cat <<EOF > /etc/systemd/system/macspoof.service
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
RestrictAddressFamilies=AF_INET
SystemCallArchitectures=native
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
EOF

      # Enables systemd service.
      systemctl enable macspoof.service
    elif [ "${which_mac_spoofer}" = "NetworkManager" ]; then
      # Installs networkmanager if it isn't already installed.
      if ! pacman -Qq networkmanager &>/dev/null; then
        read -r -p "NetworkManager is not installed. Install it now? (y/n) " install_networkmanager
        if [ "${install_networkmanager}" = "y" ]; then
          pacman -S --noconfirm -q networkmanager
        fi
      fi

      # Randomize MAC address with networkmanager.
      cat <<EOF > /etc/NetworkManager/conf.d/rand_mac.conf
[connection-mac-randomization]
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random
EOF
    fi
  fi
}

configure_umask() {
  ## Set a more restrictive umask.
  read -r -p "Set a more restrictive umask? (y/n) " umask
  if [ "${umask}" = "y" ]; then
    echo "umask 0077" > /etc/profile.d/umask.sh
  fi
}

install_usbguard() {
  ## USBGuard.
  read -r -p "Install USBGuard? (y/n) " usbguard
  if [ "${usbguard}" = "y" ]; then
    # Checks if usbguard is already installed.
    if ! pacman -Qq usbguard &>/dev/null; then
      # Installs usbguard.
      pacman -S --noconfirm -q usbguard
    fi
  fi
}

blacklist_dma() {
  ## Blacklist thunderbolt and firewire kernel modules.
  read -r -p "Blacklist Thunderbolt and Firewire? (y/n) " thunderbolt_firewire
  if [ "${thunderbolt_firewire}" = "y" ]; then
    echo "install firewire-core /bin/true
install thunderbolt /bin/true" > /etc/modprobe.d/blacklist-dma.conf
  fi
}

disable_coredumps() {
  ## Core Dumps
  read -r -p "Disable coredumps? (y/n) " coredumps
  if [ "${coredumps}" = "y" ]; then
    # Disables coredumps via sysctl.
    echo "kernel.core_pattern=|/bin/false" > /etc/sysctl.d/disable_coredumps.conf

    # Make coredump drop-in directory if it doesn't already exist.
    if ! [ -d /etc/systemd/coredump.conf.d ]; then
      mkdir /etc/systemd/coredump.conf.d
    fi

    # Disables coredumps via systemd.
    echo "[Coredump]
Storage=none" > /etc/systemd/coredump.conf.d/disable_coredumps.conf

    # Disables coredumps via limits.
    echo "* hard core 0" >> /etc/security/limits.conf

    # Prevents SUID processes from creating coredumps if not already set.
    if ! sysctl fs.suid_dumpable | grep "0" &>/dev/null; then
      echo "fs.suid_dumpable=0" > /etc/sysctl.d/suid_dumpable.conf
    fi
  fi
}

microcode_updates() {
  ## Microcode updates.
  read -r -p "Install microcode updates? (y/n) " microcode
  if [ "${microcode}" = "y" ]; then
    # Checks which CPU is being used.
    if grep 'AMD' /proc/cpuinfo >/dev/null; then
      # Install AMD ucode.
      if ! pacman -Qq amd-ucode &>/dev/null; then
        pacman -S --noconfirm -q amd-ucode
      fi

      cpu_manufacturer="amd"
    elif grep 'Intel' /proc/cpuinfo >/dev/null; then
      # Install Intel ucode.
      if ! pacman -Qq intel-ucode &>/dev/null; then
        pacman -S --noconfirm -q intel-ucode
      fi

      cpu_manufacturer="intel"
    fi

    if [ "${use_grub}" = "y" ]; then
      # Update GRUB configuration.
      grub-mkconfig -o /boot/grub/grub.cfg
    elif [ "${use_syslinux}" = "y" ]; then
      # Get current initrd configuration.
      current_initrd=$(grep -v "Fallback" /boot/syslinux/syslinux.cfg | grep -C 3 "MENU LABEL Arch Linux" | grep "INITRD")

      # Update syslinux configuration.
      sed -i "s|${current_initrd}|${current_initrd},../${cpu_manufacturer}-ucode.img|" /boot/syslinux/syslinux.cfg
    fi
  fi
}

disable_ntp() {
  ## NTP
  read -r -p "Disable NTP? (y/n) " ntp
  if [ "${ntp}" = "y" ]; then
    # Uninstalls NTP clients
    for ntp_client in ntp openntpd ntpclient
    do
      if pacman -Qq "${ntp_client}" &>/dev/null; then
        pacman -Rn --noconfirm ${ntp_client}
      fi
    done

    # Disables NTP
    timedatectl set-ntp 0
    systemctl mask systemd-timesyncd.service
  fi
}

ipv6_privacy_extensions() {
  ## IPv6 Privacy Extensions
  if [ "${disable_ipv6}" != "y" ]; then
    read -r -p "Do you want to enable IPv6 privacy extensions? (y/n) " ipv6_privacy
    if [ "${ipv6_privacy}" = "y" ]; then
      # Enable IPv6 privacy extensions via sysctl.
      echo "net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.use_tempaddr=2" > /etc/sysctl.d/ipv6_privacy.conf

      # Get list of network interfaces. Excludes loopback and virtual machine interfaces.
      net_interfaces=$(ls /sys/class/net | grep -v 'lo' | grep -v 'tun0' | grep -v "virbr")

      # Add them to ipv6_privacy.conf.
      for i in ${net_interfaces}
      do
        echo "net.ipv6.conf.${i}.use_tempaddr=2" >> /etc/sysctl.d/ipv6_privacy.conf
      done

      ## Check for NetworkManager.
      if pacman -Qq networkmanager &>/dev/null; then
        # Enable IPv6 privacy extensions for NetworkManager.
        read -r -p "Enable IPv6 privacy extensions for NetworkManager? (y/n) " networkmanager
        if [ "${networkmanager}" = "y" ]; then
          echo "[connection]
ipv6.ip6-privacy=2" >> /etc/NetworkManager/NetworkManager.conf
        fi
      fi

      ## Check for systemd-networkd.
      if systemctl is-active systemd-networkd.service >/dev/null 2>&1; then
        # Enable IPv6 privacy extensions for systemd-networkd.
        read -r -p "Enable IPv6 privacy extensions for systemd-networkd? (y/n) " systemd-networkd
        if [ "${systemd-networkd}" = "y" ]; then
          echo "[Network]
IPv6PrivacyExtensions=kernel" > /etc/systemd/network/ipv6_privacy.conf
        fi
      fi
    fi
  fi
}

blacklist_uncommon_network_protocols() {
  ## Blacklist uncommon network protocols.
  read -r -p "Blacklist uncommon network protocols? (y/n) " blacklist_net_protocols
  if [ "${blacklist_net_protocols}" = "y" ]; then
    cat <<EOF > /etc/modprobe.d/uncommon-network-protocols.conf
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install llc /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
install vivid /bin/false
EOF
  fi
}

disable_uncommon_filesystems() {
  ## Disable mounting of uncommon filesystems.
  read -r -p "Disable mounting of uncommon filesystems? (y/n) " blacklist_filesystems
  if [ "${blacklist_filesystems}" = "y" ]; then
    cat <<EOF > /etc/modprobe.d/uncommon-filesystems.conf
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install ksmbd /bin/true
install gfs2 /bin/true
EOF
  fi
}

more_entropy() {
  ## Gather more entropy.
  read -r -p "Do you want to gather more entropy? (y/n) " gather_more_entropy
  if [ "${gather_more_entropy}" = "y" ]; then
    # Enable haveged.
    if ! pacman -Qq haveged &>/dev/null; then
      read -r -p "Do you want to install and enable haveged? (y/n) " enable_haveged
      if [ "${enable_haveged}" = "y" ]; then
        pacman -S --noconfirm -q haveged
        systemctl enable haveged.service
      fi
    fi

    # Install jitterentropy.
    if ! pacman -Qq jitterentropy &>/dev/null; then
      read -r -p "Do you want to install jitterentropy? (y/n) " install_jitterentropy
      if [ "${install_jitterentropy}" = "y" ]; then
        pacman -S --noconfirm -q jitterentropy
      fi
    fi
  fi
}

webcam_and_microphone() {
  ## Block the webcam and microphone.
  read -r -p "Do you want to blacklist the webcam kernel module? (y/n) " blacklist_webcam
  if [ "${blacklist_webcam}" = "y" ]; then
    # Blacklist the webcam kernel module.
    echo "install uvcvideo /bin/true" > /etc/modprobe.d/blacklist-webcam.conf
  fi

  read -r -p "Do you want to blacklist the microphone and speaker kernel module? (y/n) " blacklist_mic
  if [ "${blacklist_mic}" = "y" ]; then
    # Blacklist the microphone and speaker kernel module.
    mic_modules=$(awk '{print $2}' /proc/asound/modules | awk '!x[$0]++')

    # Accounts for multiple sound cards.
    for i in ${mic_modules}
    do
      echo "install ${i} /bin/true" >> /etc/modprobe.d/blacklist-mic.conf
    done
  fi
}

ending() {
  ## Reboot
  read -r -p "Reboot to apply all of the changes? (y/n) " reboot
  if [ "${reboot}" = "y" ]; then
    reboot
  fi
}

read -r -p "Start? (y/n) " start
if [ "${start}" = "n" ]; then
  exit 1
elif ! [ "${start}" = "y" ]; then
  echo "You did not enter a correct character."
  exit 1
fi

update_system
script_checks
sysctl_hardening
boot_parameter_hardening
disable_nf_conntrack_helper
install_linux_hardened
apparmor
add_chaotic_aur
install_apparmor_d
get_bubblewrap
install_bubblejail
restrict_root
firewall
setup_tor
configure_hostname
block_wireless_devices
mac_address_spoofing
configure_umask
install_usbguard
blacklist_dma
disable_coredumps
microcode_updates
disable_ntp
ipv6_privacy_extensions
blacklist_uncommon_network_protocols
disable_uncommon_filesystems
more_entropy
webcam_and_microphone
ending
