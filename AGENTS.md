# Working on this repository

- Read `docs/results.md` for the measured outcome. Full-capacity write and cold-read verification passed; higher-speed SATA errors remain unresolved.
- Preserve the tested hardware-facing Python sources and hash guards. Changes for another device belong in a separate, reviewed working copy.
- Do not open physical drives, run firmware entry points, issue SMART/erase/format commands or invoke fio while maintaining this repository. All repository validation must use files and mocks.
- `work/`, firmware `.bin` files, vendor programs, private filesystem inventories and original host logs are excluded from publication.
- Public fixtures may be privacy-redacted copies. Record their original and published hashes; never label a changed copy byte-identical to the original.
- Use `python3 -B tools/verify_repository.py --offline-tests`. Add `--recovery-assets PATH` only for offline tests with locally prepared assets; never call hardware `main()` functions.
- v3/v4 intentionally bind to the historical completed write. Do not bypass SHA, serial, geometry, boot or power-cycle guards to make a different case pass.
- The default recovery precheck can load vendor code into RAM and unlock VUC commands. Describe these effects accurately.
