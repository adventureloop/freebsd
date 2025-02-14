# iwx testing:

This is a FreeBSD tree with iwx in sys/dev/iwx and a supporting Makefile.

You need to install firmware from OpenBSD to `/boot/firmware`. If you don't we
will fail to load and probably panic. To install firmware:

Grab this archive
[http://firmware.openbsd.org/firmware/7.6/iwx-firmware-20240513p0.tgz](http://firmware.openbsd.org/firmware/7.6/iwx-firmware-20240513p0.tgz)
and unpack it in /boot/firmware, if you have done this correctly it will look
like:

        $ ls /boot/firmware
        iwx-Qu-b0-hr-b0-77      iwx-QuZ-a0-hr-b0-77     iwx-so-a0-gf-a0-77      iwx-so-a0-hr-b0-77
        iwx-Qu-b0-jf-b0-77      iwx-QuZ-a0-jf-b0-77     iwx-so-a0-gf-a0.pnvm    iwx-so-a0-jf-b0-77
        iwx-Qu-c0-hr-b0-77      iwx-cc-a0-77            iwx-so-a0-gf4-a0-77     iwx-ty-a0-gf-a0-77
        iwx-Qu-c0-jf-b0-77      iwx-license             iwx-so-a0-gf4-a0.pnvm   iwx-ty-a0-gf-a0.pnvm

You may need to stop iwlwifi from attaching to the Wifi device in your
machine. You can do this by adding the following line to `/etc/rc.conf`

    devmatch_blocklist="if_iwlwifi"

and then reboot.

## Testing

First please verify that iwx has both loaded and attached to a device. You can
do this by looking at `sysctl net.wlan.devices`. If it doesn't contain `iwx0`
then the module hasn't loaded you can load it manuall:

    # kldload if_iwx

Next create a wlan device as you normally do, join a network you are familiar
with the performance of and report back:

- If iwx does or does not work
- Performance compared to your normal measurements
- If you know how, the results of `iperf`, `iperf -R` and `iperf --bidir` to a local machine
- Please provide the output of the following commands via email to thj@freebsd.org 
    - `dmesg`
    - `pciconf -lv`
    - `ifconfig wlan0`
    - `ifconfig list sta`

## Known limitations

- We don't support PRE ax210 hardware, this might result in a failure to load
  the module or a kernel panic.
- suspend and resume are **NOT** implemented
- rate selection is hard coded for 80211ac
- there is no 80211ax

FreeBSD Source:
---------------
This is the top level of the FreeBSD source directory.

FreeBSD is an operating system used to power modern servers, desktops, and embedded platforms.
A large community has continually developed it for more than thirty years.
Its advanced networking, security, and storage features have made FreeBSD the platform of choice for many of the busiest web sites and most pervasive embedded networking and storage devices.

For copyright information, please see [the file COPYRIGHT](COPYRIGHT) in this directory.
Additional copyright information also exists for some sources in this tree - please see the specific source directories for more information.

The Makefile in this directory supports a number of targets for building components (or all) of the FreeBSD source tree.
See build(7), config(8), [FreeBSD handbook on building userland](https://docs.freebsd.org/en/books/handbook/cutting-edge/#makeworld), and [Handbook for kernels](https://docs.freebsd.org/en/books/handbook/kernelconfig/) for more information, including setting make(1) variables.

For information on the CPU architectures and platforms supported by FreeBSD, see the [FreeBSD
website's Platforms page](https://www.freebsd.org/platforms/).

For official FreeBSD bootable images, see the [release page](https://download.freebsd.org/ftp/releases/ISO-IMAGES/).

Source Roadmap:
---------------
| Directory | Description |
| --------- | ----------- |
| bin | System/user commands. |
| cddl | Various commands and libraries under the Common Development and Distribution License. |
| contrib | Packages contributed by 3rd parties. |
| crypto | Cryptography stuff (see [crypto/README](crypto/README)). |
| etc | Template files for /etc. |
| gnu | Commands and libraries under the GNU General Public License (GPL) or Lesser General Public License (LGPL). Please see [gnu/COPYING](gnu/COPYING) and [gnu/COPYING.LIB](gnu/COPYING.LIB) for more information. |
| include | System include files. |
| kerberos5 | Kerberos5 (Heimdal) package. |
| lib | System libraries. |
| libexec | System daemons. |
| release | Release building Makefile & associated tools. |
| rescue | Build system for statically linked /rescue utilities. |
| sbin | System commands. |
| secure | Cryptographic libraries and commands. |
| share | Shared resources. |
| stand | Boot loader sources. |
| sys | Kernel sources (see [sys/README.md](sys/README.md)). |
| targets | Support for experimental `DIRDEPS_BUILD` |
| tests | Regression tests which can be run by Kyua.  See [tests/README](tests/README) for additional information. |
| tools | Utilities for regression testing and miscellaneous tasks. |
| usr.bin | User commands. |
| usr.sbin | System administration commands. |

For information on synchronizing your source tree with one or more of the FreeBSD Project's development branches, please see [FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/cutting-edge/#current-stable).
