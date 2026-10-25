# Third-party materials and attribution

GOODRAM and Phison own the respective product names and vendor software. This project is an independent record of a repair; it is not a vendor-approved service tool.

Firmware images, the updater, MPTool and MP_API.dll are not included. `tools/prepare_assets.py` reads user-supplied files and creates checked local artifacts. It does not download or execute vendor binaries. Published hashes and extraction offsets identify the exact inputs used in this case; they do not establish compatibility with another SSD.

Truly Crisp's [Phison S11 research](https://trulycrisp.github.io/drivefirmware/phison_s11/) and [Psychite](https://github.com/trulycrisp/psychite) informed the firmware format, loading and VUC analysis. The asset preparation tool uses a separately obtained Psychite checkout. Its source and binary algorithm tables are not vendored here. The upstream repository did not declare a license in its GitHub metadata when checked for this publication.

The case-specific workflow, offline checks and documentation were developed during this repair, with AI assistance. Existing code contains implementations informed by the cited research. No blanket MIT/Apache license is asserted over vendor material or other authors' code. Making this repository public does not change the licenses or rights of its inputs.

fio and smartmontools produced the selected diagnostic outputs. Neither program is bundled. Output files preserve factual measurements; privacy redactions are documented in `docs/evidence.md` and the provenance manifest.
