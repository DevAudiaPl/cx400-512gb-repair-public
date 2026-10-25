# Public evidence and provenance

The public repository is a selected release of a private working archive. The original files and failed experiments remain private. Public history starts separately and contains no earlier private commits.

## Included

- The original full-write and full-read fio JSON, preserved byte for byte because their hashes are part of the historical verification chain.
- Historical write state and selected per-drive SMART snapshots. The generated repair serial and power-cycle counts connect the write/read evidence.
- Targeted kernel output from the data tests, stderr, job configurations and the original Flash ID output.
- A derived recovery summary with the raw private report's SHA, command counts and the successful final result.
- Case-specific recovery/test source. Hardware-facing source hashes are retained; original Polish diagnostics remain in those historical files.

## Excluded or redacted

Private filesystem inventories, user home paths, account names, unrelated drive identifiers, unredacted host-wide dmesg/lsblk output, MAC addresses, private archive links and the earlier conversation link are not part of this publication. A redacted device-selection fixture retains the mounted-system-disk structure needed to test target selection.

Selected text/JSON fixtures replace private home paths with `/home/operator` and remove WWN fields from SMART copies. Test-only examples of the unrelated healthy drive use a synthetic identifier. These are privacy-redacted copies, not byte-identical originals.

`manifests/artifacts.json` records the published SHA-256/size for included artifacts and the original SHA where a source copy exists. Its transformation field makes redactions explicit. Source paths in this public manifest are repository-relative labels; it does not contain the private computer's directory inventory.

The generated repaired-drive serial, timestamps, technical port/device paths and original random boot IDs used as cold-cycle proof are retained where needed. They are diagnostic evidence, not reusable setup values or credentials.

Firmware `.bin`, vendor EXE/DLL files, raw RAM/NAND dumps and packaged private results are excluded. Required images can be [prepared locally](assets.md) from checked inputs. Hashes for omitted originals identify archived evidence; they do not make those originals publicly available or constitute independent third-party attestation.

## Validation scope

```sh
python3 -B tools/verify_repository.py --offline-tests
```

The public-only check verifies artifact hashes, links, capacity/pattern/cold-cycle evidence and100 offline checks:58 data/guard checks,12 fio-parser regression tests and15 checks for each read-only verifier. It does not silently claim firmware validation when vendor assets are absent.

Adding `--recovery-assets PATH` requires all expected local assets and runs the additional236 mock-transport/content checks, for336 total. No validation command opens the SSD or invokes hardware entry points.
