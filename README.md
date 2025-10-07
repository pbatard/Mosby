[![Build Status](https://img.shields.io/github/actions/workflow/status/pbatard/Mosby/Linux.yml?style=flat-square&label=Linux/EDK2%20Build)](https://github.com/pbatard/Mosby/actions/workflows/Linux.yml)
[![Release](https://img.shields.io/github/release/pbatard/Mosby.svg?style=flat-square&label=Release)](https://github.com/pbatard/Mosby/releases)
[![Licence](https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square&label=License)](https://www.gnu.org/licenses/gpl-3.0)
[![Downloads](https://img.shields.io/github/downloads/pbatard/Mosby/total.svg?label=Downloads&style=flat-square)](https://github.com/pbatard/Mosby/releases)

Mosby - More Secure Secure Boot
===============================

## Description

**Mosby** (*mos⸱bee*), which stands for *More Secure Secure Boot, for **You***, is a UEFI
Shell application designed to easily create and install a more secure (and more up to date)
default set of UEFI Secure Boot keys that includes your own Secure Boot signing credentials,
as well as a **unique**, non-exploitable, machine Primary Key (PK).

The motivations behind this are as follows:

1. Two of the Secure Boot whitelisting (*DB*) certificates, commonly used for Secure Boot
   validation (`Microsoft Windows Production PCA 2011` and `Microsoft Corporation UEFI CA 2011`)
   as well as Microsoft's main Key Exchange Key (*KEK*) certificate
   (`Microsoft Corporation KEK CA 2011`) **are set to expire in the second half of 2026**.  
   Whereas, in itself, this will not prevent **existing** Secure Boot signed bootloaders from
   validating (as long as they haven't been revoked through other means) it will however
   prevent any **newer** UEFI bootloader from doing so which basically means that, if your OS
   or OS installer was produced after those DB certificates expire, and you don't have the
   additional 2023 DB certificates installed (see below), then, come the second half of 2026,
   you will not be able to boot or even install a Secure Boot compatible OS in a Secure Boot
   enabled environment!  
   This application can remedy that.
2. In 2023, because of the expiration of the certificates listed above, Microsoft introduced
   one new *KEK* and two new *DB* certificates, that are therefore not commonly found in your
   system manufacturer's default key (especially if your system has not received any firmware
   update since 2024) and that (because a *KEK* can **only** be installed through
   [updates that are signed by the platform manufacturer](https://uefi.org/specs/UEFI/2.9_A/32_Secure_Boot_and_Driver_Signing.html#enrolling-key-exchange-keys))
   can be problematic to update from the OS itself, even if the OS is Secure Boot compatible
   or comes from Microsoft.  
   This application can remedy that.
3. As of the second half of 2024, and due to
   [many](https://arstechnica.com/information-technology/2023/03/unkillable-uefi-malware-bypassing-secure-boot-enabled-by-unpatchable-windows-flaw/),
   [many](https://wack0.github.io/dubiousdisk/) vulnerabilities uncovered in the UEFI Windows
   bootloaders, Microsoft is in the process of **completely removing** one of the base DB
   certificates (The `Microsoft Windows Production PCA 2011` certificate mentioned above).  
   **Once Microsoft produces installation media that no longer uses this certificate**,
   this application will make sure that this DB certificate is properly removed (as opposed
   to what would happen if you use the native Secure Boot key restoration from your UEFI
   firmware).
4. In 2024, it was discovered that some PC manufacturers [played fast and loose with the
   Primary Key (*PK*) shipped with their hardware](https://arstechnica.com/security/2024/07/secure-boot-is-completely-compromised-on-200-models-from-5-big-device-makers/),
   basically meaning that malicious actors could gain access to the secret key, and therefore
   gain full trusted access of the affected machines. It is also very likely (though of
   course it is in their interest not to reveal it) that, PC manufacturers have had more *PK*
   private key exfiltered into the hand of malicious actors (or, if you are living under an
   authoritative regime, have been forced to hand them over to said regime), leading to the
   same very real risk of a third parties exploiting this data to install UEFI rootkits on
   users' computers.  
   With its default settings, this application can fully remedy that.
5. As part of the 2023 certificate update, Microsoft is also introducing a new dedicated
   Secure Boot certificate for Option ROMs, which older UEFI firmwares do not have and which
   may prevent add-on cards from being able to initialize in a Secure Boot environment.
   This application can remedy that.
6. OS manufacturers, such as Microsoft, have long taken a very user-adverse stance against
   the ability of individuals to ultimately be in control the UEFI boot signing process, by,
   to name just a few instances, using fake rhetoric against some software licenses in order
   to arbitrarily deny common Linux bootloaders such as GRUB from being Secure Boot signed,
   trying to lock down hardware so that Secure Boot could not ever been disabled by the user,
   making a two-tier version of Secure Boot signatures with one exclusive tier for Windows
   and a lower tier for other OSes and application or, up until recently, even trying to
   prevent anybody that wasn't an OS or hardware manufacturer from being allowed to
   redistribute UEFI revocation lists...  
   The end result is that it has become a lot more convoluted and daunting than it should
   really be for end-users, to make Secure Boot work in their favour.  
   This application can also remedy that.
7. Figuring out SBAT, SkuSiPolicy as well as Microsoft's new SVN DBX based revocation updates
   is currently a mess, as you need to wade through many different sources to try to ensure
   that your system is actually up to date with them (because if they aren't, an attacker can
   easily bypass Secure Boot on your system).  
   This application can remedy that.

In short, while making sure that all the Secure Boot keys used by your platform are up to
date, the whole point of this application is to give control of the whole Secure Boot process
back to **YOU**, like it should always have been, instead of leaving it in control of a
select few, who may not have your interests in mind, and, over and over, have demonstrated
behaviour that should not warrant your blind trust.

And it does so by making incredibly **easy** to install your own set of Secure Boot keys.

## Usage

1. Create a UEFI Shell bootable media.  
   If you don't have such a media, you can *easily*  create one on Windows through
   [Rufus](https://rufus.ie) by using the SELECT/DOWNLOAD split button and then choosing
   *UEFI Shell* in the download selection:  
   https://raw.githubusercontent.com/wiki/pbatard/rufus/images/download.gif

2. Extract all the content from the latest Mosby download archive at the top level of the
   boot media you created in the previous step.

3. Boot the computer where you want to install the keys into the UEFI firmware settings and
   make sure that your platform is in *Setup Mode*. Please refer to your manufacturer's
   documentation if you don't know how to enable *Setup Mode*.

4. Boot into the UEFI Shell media you created and type: `Mosby` (without any extension). The
   executable relevant to your platform will automatically launch and will guide you through
   the installation of the UEFI Secure Boot keys.

5. Once the installation is complete, reboot into UEFI firmware settings, and make sure that
   Secure Boot is enabled.

If needed, you can also provide your own DB/DBX/DBT/KEK/PK/MOK binaries in DER, PEM, ESL or
signed ESL format, by using something like `-db canonical_ca.cer` to point a Secure Boot
variable to the data you want to install for it.

## Parameters

* `-h`: Display the application parameters and exit.
* `-v`: Display the application version and exit.
* `-i`: Display information about the embedded data installable by the application, as well
        as the current SBAT data from the system (if SBAT is set).
* `-s`: Silent option (Removes some of the early and late prompts).
* `-u`: Update only: Only update the revocation databases, SBAT, and SSPV/SSPU as needed.
* `-t`: Test mode. Disables some checks and enables the internal **low security** Random
        Number Generator, if no other Random Number Generator can be found.
* `-x`: Install the Microsoft update that invalidates `Microsoft Windows Production PCA 2011`.
        You should only use this if you know what you are doing, as you you may not be able
        to boot or reinstall Windows otherwise. **You have been warned!**

You can also point to files using the `-pk`, `-kek`, `-db`, `-dbx`, `-mok`, `-dbt`, `-sbat`,
`-sspv` and `-sspu` parameters.

## Compilation

Because Mosby depends on OpenSSL to provide the various cryptography function it needs, and
OpenSSL is integrated by default into [EDK2](https://github.com/tianocore/edk2), only EDK2 is
supported for compilation.

Additionally, some very limited patching of EDK2 is required to enable some of the standard
OpenSSL providers, that take care of the importing/exporting of keys and certificates, and
that are not currently enabled by EDK2.
So you should first apply `Add-extra-PKCS-encoding-and-decoding-to-OpensslLibFull.patch` to
the EDK2 submodule.

If compiling for ARM or RISCV-64 some additional patching of OpenSSL is required, that can be
found in `OpenSSL-submodule-fixes-for-<PLATFORM>-compilation.patch`.

Once that is done, you can compile Mosby as you would any regular EDK2 module, by issuing
something like:

```
cd <directory where you cloned Mosby>
git submodule update --init
export WORKSPACE=$PWD
export PACKAGES_PATH=$WORKSPACE:$WORKSPACE/edk2
source edk2/edksetup.sh
build -a X64 -b RELEASE -t GCC5 -p MosbyPkg.dsc
```

Note that, if you have `bash` with `curl`, `OpenSSL` and `sed` installed, you can recreate
`data.c` by running the following command in the `src/` directory:
```
./gen_data.sh > data.c
```

## Mini FAQ

### ERROR: This platform does not meet the minimum security requirements

If you are getting the error above, it usually means that your system is lacking a proper
random number generator, which is essential for the generation of a Secure Boot signing key
that can't be easily cracked by an attacker.

Mosby first attempts to use the OpenSSL provided random number generator or, if that is not
available, it falls back to using the UEFI platform's random number generator both of which
are considered safe for the generation of signing keys.

If none of the above are available, then Mosby can also use its own internal random number
generator, however because of the algorithm being used, this generator should be considered
**unsafe** and therefore can only be used when running Mosby with the "test" (`-t`) option.

### How do I use the generated Secure Boot key to sign a UEFI bootloader?

* On Windows, use `signtool.exe` with the `.pfx`. For example, to sign `bootx64.efi`:
```
signtool sign /f MosbyKey.pfx /fd SHA256 bootx64.efi
```

Note that you can download `signtool.exe` with the command:
```
curl.exe -L -A "Microsoft-Symbol-Server/10.0.0.0" https://msdl.microsoft.com/download/symbols/signtool.exe/910D667173000/signtool.exe -o signtool.exe
```

* On Linux, use `sbsign` from the `sbsigntool` package with the `.pem` and `.crt`.
  For example, to sign `bootx64.efi`:

```
sbsign --key MosbyKey.pem --cert MosbyKey.crt bootx64.efi --output bootx64.efi
```

If asked for a passphrase, just press <kbd>Enter</kbd>.

### How can you state that your application makes Secure Boot more Secure?

Easy. If you had used `Mosby` then even on a PC where the default UEFI keys were subject to
[this vulnerability](https://it.slashdot.org/story/24/07/25/2028258/secure-boot-is-completely-broken-on-200-models-from-5-big-device-makers),
the vulnerability would have been fully closed and rendered inexploitable.

### Why isn't the Secure Boot private key generated by this application password protected?

Because the key is unique, and, in most usage scenarios (individuals securing a very limited
number of machines) unlikely to be easy to exploit (since the attacker would already need to
have found a vulnerability to locate and access the key from where it is stored). On the
other hand, we want to make it easy for people to be able to sign their UEFI bootloaders as
they need it, because vetting bootloaders for Secure Boot should not be a daunting prospect.

At any rate, if you do want a Secure Boot signing key that is protected by a password, you
can easily generated one with OpenSSL, and then point to its matching certificate when
running `Mosby`.

### How can I trust that Mosby is not doing something malicious behind the scenes?

1. It's public source, using a license that **explicitly prevents** the inclusion of anything
   in the final binary for which you cannot access the source.
2. It's built in a transparent manner through GitHub Actions, and binary validation can be
   enacted in a similar way as
   [what applies to our UEFI-Shell binaries](https://github.com/pbatard/UEFI-Shell?tab=readme-ov-file#binary-validation).
3. It's published by the same developer as the person behind [Rufus](https://rufus.ie), which
   is a rather popular and **trusted** application, that, for more than 10 years now, has
   helped countless people install bootloaders and run privileged code on their computer. In
   short if the ultimate goal of the developer of Mosby was to gain the ability to exploit
   your computer, they would have had plenty of other opportunities to do so over the last
   decade, and, more importantly, would long have been reported if they ever did so.
