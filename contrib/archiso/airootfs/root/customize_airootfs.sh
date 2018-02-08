#!/bin/bash

set -e -u

sed -i 's/#\(en_US\.UTF-8\)/\1/' /etc/locale.gen
locale-gen

ln -sf /usr/share/zoneinfo/UTC /etc/localtime

usermod -s /usr/bin/zsh root
cp -aT /etc/skel/ /root/
chmod 700 /root

! id kovri && useradd -m -s /bin/bash -G docker kovri
cp -aT /etc/skel/ /home/kovri
chmod 700 /home/kovri

sed -i 's/#\(PermitRootLogin \).\+/\1yes/' /etc/ssh/sshd_config
sed -i "s/#Server/Server/g" /etc/pacman.d/mirrorlist
sed -i 's/#\(Storage=\)auto/\1volatile/' /etc/systemd/journald.conf

sed -i 's/#\(HandleSuspendKey=\)suspend/\1ignore/' /etc/systemd/logind.conf
sed -i 's/#\(HandleHibernateKey=\)hibernate/\1ignore/' /etc/systemd/logind.conf
sed -i 's/#\(HandleLidSwitch=\)suspend/\1ignore/' /etc/systemd/logind.conf

systemctl enable pacman-init.service choose-mirror.service
systemctl set-default multi-user.target
systemctl poweroff -i

# Clone latest Kovri repo if it doesn't exist
if [[ ! -d /usr/src/kovri ]]; then
  git clone --recursive https://github.com/monero-project/kovri.git /usr/src/kovri
fi

# Build and install Kovri
cd /usr/src/kovri && KOVRI_DATA_PATH=/home/kovri/.kovri make -j$(nproc) release && make install
chown -R kovri:kovri /home/kovri
ln -sf /usr/src/kovri/build/{kovri,kovri-util} /usr/bin

## # Clone latest Monero repo if it doesn't exist
## if [[ ! -d /usr/src/monero ]]; then
##   git clone https://github.com/monero-project/monero.git /usr/src/monero
## fi
## 
## # Build and install Monero 
## cd /usr/src/monero && make -j$(nproc) release-static-linux-x86_64
## ln -sf /usr/src/monero/build/release/bin/* /usr/bin 
