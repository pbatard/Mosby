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
   or OS installater was produced after those DB certificates expire, and you don't have the
   additional 2023 DB certificates installed (see below), then, come the second half of 2026,
   you will not be able to boot or even install a Secure Boot compatible OS in a Secure Boot
   enabled environment!  
   This application can remedy that.
2. In 2023, because of the expiration of the certificates listed above, Microsoft introduced
   one new *KEK* and two new *DB* certificates, that are erefore not be commonly found in your
   system manufacturer's default key (especially if your system has not received any firmware
   update since 2024) and that (because a *KEK* can **only** be installed through updates
   [that are signed by the platform manufacturer](https://uefi.org/specs/UEFI/2.9_A/32_Secure_Boot_and_Driver_Signing.html#enrolling-key-exchange-keys))
   cannot be fully updated from the OS itself, even if the OS is Secure Boot compatible or
   comes from Micosoft.  
   This application can remedy that.
3. As of the second half of 2024, and due to
   [many](https://arstechnica.com/information-technology/2023/03/unkillable-uefi-malware-bypassing-secure-boot-enabled-by-unpatchable-windows-flaw/),
   [many](https://wack0.github.io/dubiousdisk/) vulnerabilities uncovered in the UEFI Windows
   bootloaders, Microsoft is in the process of **completely removing** one of the base DB
   certificates that it has been using to sign its UEFI executables since 2011.  
   This application can make sure that this DB certificate is properly removed (as opposed to
   what will happen if you use the native Secure Boot key restoration from your UEFI
   firmware).
4. In 2024, it was disovered that some PC manufacturers [played fast and loose with the
   Primary Key (*PK*) shipped with their hardware](https://arstechnica.com/security/2024/07/secure-boot-is-completely-compromised-on-200-models-from-5-big-device-makers/),
   basically meaning that malicious actors could gain access to the secret key, and therefore
   gain full trusted access of the affected machines. It is also very likely (though of
   course it is in their interest not to reveal it) that, PC manufacturers have had more *PK*
   private key exfiltered into the hand of malicious actors (or, if you are living under an
   authoritative regime, have been forced to hand them over to said regime), leading to the
   same very real risk of a third parties exploiting this data to install UEFI rootkits on
   users' computers.  
   With its default settings, this application can fully remedy that.
5. OS manufacturers, such as Microsoft, have long taken a very user-adverse stance against
   the ability of individuals to ultimately be in control the UEFI boot signing process, by,
   to name just a few instances, using fake rethoric against some software licenses in order
   to arbitrarily deny common Linux bootloaders such as GRUB from being Secure Boot signed,
   trying to lock down hardware so that Secure Boot could not ever been disabled by the user,
   making a two-tier version of Secure Boot signatures with one exclusive tier for Windows
   and a lower tier for other OSes and application or even trying to prevent anybody that is
   not an OS or hardware manufacturer from being allowed to redistribute the UEFI revocation
   lists...  
   The end result is that it has become a lot more convoluted and daunting than it should
   really be for end-users, to make Secure Boot work in their favour.  
   This application can also remedy that.

In short, while making sure that all the Secure Boot keys used by your platform are up to
date, the whole point of this application is to give control of the whole Secure Boot process
back to **YOU**, like it should always have been, instead of leaving it in control of a
select few, who may not have your interests in mind, and, over and over, have demonstrated
behaviour that should not warrant your blind trust.

And it does so by making incredibly **easy** to install your own set of Secure Boot keys.

## Usage

[TODO]

## MosbyList.txt format

[TODO]

## Support file download

If using the default `MosbyList.txt` from this repository, you will need to
download the required support files by issuing the following commands (which
should work from the commandline on any recent Windows or Linux machine):
```
curl --create-dirs -L https://go.microsoft.com/fwlink/?LinkId=321185 -o certs/kek_ms1.cer
curl --create-dirs -L https://go.microsoft.com/fwlink/?linkid=2239775 -o certs/kek_ms2.cer
curl --create-dirs -L https://go.microsoft.com/fwlink/?linkid=321192 -o certs/db_ms1.cer
curl --create-dirs -L https://go.microsoft.com/fwlink/?linkid=321194 -o certs/db_ms2.cer
curl --create-dirs -L https://go.microsoft.com/fwlink/?linkid=2239776 -o certs/db_ms3.cer
curl --create-dirs -L https://go.microsoft.com/fwlink/?linkid=2239872 -o certs/db_ms4.cer
curl --create-dirs -L https://uefi.org/sites/default/files/resources/x86_DBXUpdate.bin -o dbx/dbx_ia32.bin
curl --create-dirs -L https://uefi.org/sites/default/files/resources/x64_DBXUpdate.bin -o dbx/dbx_x64.bin
curl --create-dirs -L https://uefi.org/sites/default/files/resources/arm_DBXUpdate.bin -o dbx/dbx_arm.bin
curl --create-dirs -L https://uefi.org/sites/default/files/resources/arm64_DBXUpdate.bin -o dbx/dbx_aa64.bin
```

Note that the most recent version of these files (at the time a the release was created) is
provided in the release archive.

## Compilation

[TODO]

## Mini FAQ

### How do I use the generated Secure Boot key to sign a UEFI bootloader?

* On Windows, use `signtool.exe` with the `.pfx`. For example, to sign `bootx64.efi`:
```
signtool sign /f "Mosby Secure Boot Signing.pfx" /fd SHA256 bootx64.efi
```

Note that you can download `signtool.exe` with the command:
```
curl.exe -L -A "Microsoft-Symbol-Server/10.0.0.0" https://msdl.microsoft.com/download/symbols/signtool.exe/910D667173000/signtool.exe -o signtool.exe
```

* On Linux, use `sbsign` from the `sbsigntool` package with the `.pem` and `.crt`.
  For example, to sign `bootx64.efi`:

```
sbsign --key "Mosby Secure Boot Signing.pem" --cert "Mosby Secure Boot Signing.crt" bootx64.efi --output bootx64.efi
```

If asked for a passphrase, just press <kbd>Enter</kbd>.

### How can you state that your application makes Secure Boot more Secure?

Easy. If you had used `Mosby` with the default list file, then even on a PC where the default
UEFI keys were subject to
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
