# Adapting this case to another SSD

This is a preserved successful case with deliberate device/content guards. A matching product label alone does not authorize changing constants until a STOP disappears.

## Recovery guards

| Guard | Historical value | Required review |
|---|---|---|
| Controller and ROM | PS3111 / SBRM02.0 | Confirm exact controller/firmware state |
| NAND ID | `98 3e 99 b3 7a 72 08 06` | Confirm every CE and geometry, not just capacity |
| CE indices | `0,1,2,3,8,9,10,11` | Confirm populated channels/CEs and compatible images |
| Burner | SATABURN SB / SBBQ61L3 | Other code needs separate loading/protocol analysis |
| RAM controls | Two known control words | Validate actual image/layout; do not skip checks |
| Assets manifest | SHA-256 pinned in the recovery source | Keep original verified bytes; another image needs a new independently reviewed manifest |
| Link | `ata4/link4`, measured 1.5 Gb/s | Determine the real host port from sysfs and kernel logs |

Flash ID readout establishes identity; it does not prove successful NAND erase/programming. ATA status `0x51` is not a NAND diagnosis by itself: inspect the error register, sense data, command and firmware state.

The repair assigns a new serial during PreFormat. Use the actual serial reported after a cold start when preparing the later test. Do not assign the historical example serial to another SSD just to satisfy guards.

## A new write/read cycle

Start with a separate working copy of `scripts/final-test-v2`. Set `SERIAL` to the actual target. Retain the fixed capacity/firmware only if confirmed. Match the target by identity and geometry, not a remembered `/dev/sdX` letter.

The historical `cx400-test.py` v2 explicitly rejects a forced 1.5 Gb/s boot argument. The successful original write started at 3 Gb/s and the kernel reduced the speed after bus errors. A new test on the affected host should instead use a reviewed guard requiring its stable 1.5 Gb/s configuration.

The original block in `main()` is:

```python
check_smart(smart(device,'smart-immediate-before'))
need('libata.force=4:1.5' not in Path('/proc/cmdline').read_text(),
     'Test końcowy uruchom bez wymuszenia1.5Gbps')
```

For the confirmed `ata4` host, a proposed replacement would require all three checks below:

```python
immediate = smart(device, 'smart-immediate-before')
check_smart(immediate)
tokens = Path('/proc/cmdline').read_text().split()
need(re.search(r'/ata4/', str(path)), 'Target is not on ata4')
need([t for t in tokens if t.startswith('libata.force=')]
     == ['libata.force=4:1.5Gbps'], 'Required SATA limit is missing')
need(immediate.get('interface_speed', {}).get('current', {}).get('sata_value') == 1,
     'SMART does not confirm a 1.5 Gb/s link')
```

**This is an adaptation proposal, not the code that performed the historical write.** For a different host, review both references to port4 and confirm the resolved device path. Test changed port/speed guards on mocks before using the copy on hardware; passing the original offline tests does not validate a newly edited block.

The same prepared `cx400-test.py` supports `write` and `verify`, with state retained across power removal. The included v3/v4 scripts are tied to the historical `CORE_SHA`, `WRITE_SHA`, `WRITE_FOLDER` and generated serial. A new write necessarily produces a different report hash and needs its own reviewed proof. Preserve every identity, content, completion and cold-cycle check when preparing another verifier.
