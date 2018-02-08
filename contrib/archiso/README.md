# Creating a Kovri Development & Testnet ISO with Archiso

Here are some instructions for creating a live usb for testing and/or developing Kovri.

The live usb image is based on Arch linux and the Archiso toolset.

## Prerequisites
- Arch Linux system
- archiso

## Build instructions

Detailed instructions for building and customizing the archiso profile is available on the [Arch
wiki](https://wiki.archlinux.org/index.php/Archiso)

The testnet ISO is based on the `releng` archiso profile, with customizations to install Kovri and it's dependencies.

To build the ISO:
```
$ cd /path/to/kovri/contrib/archiso
# ./build.sh [-N your_iso_name] [-v]
```

After running the above command, your ISO will be in `out/your_iso_name.iso`.

# Rebuilding instructions

If you built the ISO, and want to make further changes (installing packages, configuration, etc), then you can rebuild
the ISO.

You will need to remove pacman's lock files, and run `build.sh` again:
```
cd /path/to/kovri/contrib/archiso
rm -v work/build_*
```

## Preparing the live media

There are different setups required for a development or testnet ISO.

### Development LiveUSB 

The development ISO is the easiest to prepare. 

#### WARNING: dd can overwrite your system drive, ensure you write to the proper drive

Insert a USB and write the ISO:
```
$ cd /path/to/kovri/contrib/archiso
# dd if=out/your_iso_name.iso of=/dev/sdX bs=1M
```

In the above command, `/dev/sdX` is the path to your USB, where `X` is the proper drive letter.

### Testnet LiveUSB

The first part of preparing the testnet USB is the same.

#### WARNING: dd can overwrite your system drive, ensure you write to the proper drive

Insert a USB and write the ISO:
```
$ cd /path/to/kovri/contrib/archiso
# dd if=out/your_iso_name.iso of=/dev/sdX bs=1M
```

In the above command, `/dev/sdX` is the path to your USB, where `X` is the proper drive letter.

Now you need to add a partition to the USB for the testnet Docker images:
```
# fdisk /dev/sdX
Command (m for help): n
Command action
p
[enter] # select the default beginning sector for the new partition
+2G     # make a 2GiB paritition
w       # write your changes to the disk
# mkfs.ext4 -O "^has_journal" /dev/sdXN # create filesystem, X = drive letter, N = partition number
```

After creating the partition, you will need to mount it after booting the LiveUSB:
```
press CTRL+ALT+F2 to open tty2
login as root (no password by default)
# mkdir /tmp/docker
# mount /dev/sdXN /tmp/docker # X = drive letter, N = partition number
```

Docker needs to know about your new partition:
```
# vim /etc/docker/daemon.json
...
"graph" : "/tmp/docker"
...
```

Changing the `graph` parameter tells Docker where to store images.

Now start the daemon:
```
# systemctl start docker
```

You can now switch back to the `kovri` user in `tty1`, and create the testnet:
```
press CTRL+ALT+F1 to open tty1
$ cd /tmp/kovri
$ ./contrib/testnet/testnet.sh create
```
