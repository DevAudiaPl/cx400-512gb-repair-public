# Preparing the firmware assets locally

Firmware, the Windows updater and MPTool binaries are excluded from this repository. Obtain your own copies of the exact inputs below. The preparation tool checks their complete SHA-256 before parsing anything and refuses different versions. There is no download or execution of vendor EXE/DLL files.

| Input | Expected SHA-256 |
|---|---|
| GOODRAM `fw-SBFM61.3-20210311.exe` | `1e071b93ec8e629d9bdb6b7222432594a998afcc09df6e9fbea843227e384a93` |
| MPTool `Bin/SBFQ61L3.BIN` | `440c6246d332826ffc2a8ca4411e48bd78bded67c36e194b912f6c71f89eeb55` |
| MPTool v2.2.85 `MP_API.dll` | `87a3455e5cfc41de3c65854f17bd47ce8b42dbefbf4d9f43e67a8e38ca2f8455` |

Availability of these historical files is not guaranteed. A similarly named file, another SBFM61.x build or a replacement image is not an accepted substitute.

The parser is the separately obtained [Psychite](https://github.com/trulycrisp/psychite) project. Python 3.13 is recommended. For a reproducible checkout:

```sh
git clone https://github.com/trulycrisp/psychite.git work/psychite
git -C work/psychite checkout 15a8a845566903e2b1824bcf8da043848a187fdc
```

Run from this repository's root, replacing the three example input paths:

```sh
python3 -B tools/prepare_assets.py \
  --updater /path/to/fw-SBFM61.3-20210311.exe \
  --burner /path/to/Bin/SBFQ61L3.BIN \
  --mp-api /path/to/MP_API.dll \
  --psychite work/psychite \
  --output work/recovery-v2
```

This creates the firmware sections, templates and static regression assets needed by the unchanged recovery code. Every generated file must match `scripts/recovery-v2/assets.json`; the full normal image must hash to `c73d0b4d06bc44be913f4876f9fc21935ca4f6f51fce3b2c4f95f80add3f7d1e`. Existing different destination files cause a stop instead of being overwritten.

The preparation helper is an offline packaging addition for the public release. Its output is checked against the archived assets that were used in the successful hardware run. It does not itself communicate with the SSD.

```sh
python3 -B tools/verify_repository.py --offline-tests --recovery-assets work/recovery-v2
```

The public repository ignores all `.bin` files and `work/`. Keep generated vendor assets local. Their valid hashes establish correspondence to this case, not suitability for a different NAND configuration.
