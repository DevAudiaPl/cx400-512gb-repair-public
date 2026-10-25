# Why the corrected sequence worked

These findings describe the exact images and captured commands in this case. They are not a universal PS3111 specification.

## ROM, burner and installed firmware

`PS3111 / SBRM02.0` with 0/20 MB indicated failure to start the normal firmware. Standard InfoBlock reads could be rejected while vendor commands still read NAND IDs.

SBBQ61L3 is service code loaded into RAM. A successful RAM load or an updater's “Update successful” message does not establish durable installation of normal SBFM61.3. The controller can continue identifying as a burner after commit until power is removed.

The loading/VUC analysis was informed by [Truly Crisp's S11 research](https://trulycrisp.github.io/drivefirmware/phison_s11/) and Psychite. The case-specific workflow is preserved in `scripts/recovery-v2`.

## Erase09: the decisive byte

| Observation | Value |
|---|---|
| Receiver check | SBBQ61L3 code at `0x60015484..0x600154A7` |
| Independent host implementation | MP_API.dll v2.2.85, function at `0x10073460` |
| Rejected command frame | `a10a262601000009a0310000` |
| Accepted corrected frame | **`a10a262601880009a0310000`** |
| Correct 24-bit LBA | `(9 << 16) | 0x88` = `0x090088` |
| Earlier attempt | Immediate ATA ABRT/error04/status51 |
| Corrected attempt | Erase09 completed in 16.384962 seconds |

The receiver's mode09 branch requires **LBA Low `0x88`**. The earlier Linux implementation sent `0x00` and hit an explicit rejection branch before the erase. This was a diagnosed command construction bug, not evidence that the NAND was physically dead.

The local asset-preparation tool extracts the relevant receiver and host slices from the checked vendor files. Offline tests check their original hashes, the receiver's immediate value and the independently encoded host mode09 selection before testing the corrected command builder. Vendor instruction bytes are not bundled in the public repository.

## Complete sequence after the correction

| Stage | Command/check | Observed outcome |
|---|---|---|
| First erase | EraseAll09 with Low88 | 16.384962 s |
| Second erase | EraseAll05 | 21.270436 s |
| PreFormat | VUC08 with prepared InfoBlock + SMART | 10.967796 s; InfoBlock flag set |
| Seed | VUC80, first 16 KiB of normal image | Table/key matched `0x71494F27` |
| Code transfer | VUC82, 12 chunks | Final CRC marker `BB` |
| Pre-commit validation | All six SRAM sections | Contents and checksums matched |
| Commit | VUC41 | 0.222549 s |
| NAND readback | VUC31, 4,096-byte header and entire code | Matched the original image |

The normal image is 786,432 bytes: a 16,384-byte seed plus 770,048 bytes of code. The whole programmed code was read back and compared.

| Artifact | SHA-256 |
|---|---|
| Normal SBFM61.3 image | `c73d0b4d06bc44be913f4876f9fc21935ca4f6f51fce3b2c4f95f80add3f7d1e` |
| Programmed code read from NAND | `bbd7764602bb65e08eeb60e52adbc6ea8587d8c88a4ed1a8ed9474c7d6c473d4` |
| Header read from NAND | `f608138e0be8d7d8d8d4f0cac6f9b23df0d7eabaa25a93c0b1853067c9922853` |

Normal boot after power removal and [full user-data verification](results.md) were separate completion criteria. The original cause of firmware failure and every earlier Windows error remain unproven.
