# Sources and attribution

The case findings are based on captured ATA responses, static image analysis, actual NAND readback and full-capacity fio/SMART evidence. Facts established by those records are distinguished from unresolved causes and proposed adaptations.

| Primary source | Use |
|---|---|
| [Truly Crisp — Phison S11](https://trulycrisp.github.io/drivefirmware/phison_s11/) | RAM loading, VUC and firmware-format research |
| [Psychite](https://github.com/trulycrisp/psychite) | Independent firmware parsing and algorithms used during the analysis; obtained separately |
| [Kernel6.12 parameters](https://www.kernel.org/doc/html/v6.12/admin-guide/kernel-parameters.html) | `libata.force` syntax and port/link limits |
| [libATA](https://docs.kernel.org/driver-api/libata.html) | Error handling and link-speed reduction |
| [PCI MSI documentation](https://docs.kernel.org/PCI/msi-howto.html#disabling-msis-globally) | Meaning of `pci=nomsi` |
| [Kernel I/O statistics](https://www.kernel.org/doc/html/latest/admin-guide/iostats.html) | Byte-progress calculations from sysfs |
| [fio3.39 verification source](https://github.com/axboe/fio/blob/fio-3.39/verify.c) | Pattern comparison, offsets and header checks |
| [fio manual](https://fio.readthedocs.io/en/latest/fio_doc.html) | Job and verification options |
| [Debian Trixie smartctl manual](https://manpages.debian.org/trixie/smartmontools/smartctl.8.en.html) | SMART, device statistics and SATA PHY events |
| [smartmontools drive database](https://github.com/smartmontools/smartmontools/blob/master/smartmontools/drivedb.h) | Phison OEM attribute interpretation |

The [earlier community discussion](https://www.elektroda.pl/rtvforum/topic3859967.html) provided context for Windows tools and USB bridge attempts. Those reports are not a compatibility specification or proof that a particular bridge repairs every S11 device.

The public asset-preparation instructions pin Psychite commit `15a8a845566903e2b1824bcf8da043848a187fdc`. All generated outputs must still match the original checked asset hashes. Vendor input hashes are listed in [Preparing assets](assets.md). Existing online copies may disappear or differ from those exact inputs.

See [THIRD_PARTY.md](../THIRD_PARTY.md) for the distribution boundaries. No firmware or external parser code is bundled here.
