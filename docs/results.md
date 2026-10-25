# Verified outcome and limitations

The restored user area accepted a complete write and returned the same data after physical power removal. Stable cold-read verification was performed at **SATA 1.5 Gb/s**. Errors at 3 Gb/s remain a limitation of the tested host/caddy/SSD combination.

| Stage | Public evidence | Outcome |
|---|---|---|
| Firmware programming | [Derived recovery summary](../evidence/recovery-summary.json) | 481 commands, complete programmed-code readback matched |
| User-data write | [Original fio JSON](../evidence/final-write-003327/cx400-full.json) | 512,110,190,592 bytes, both jobs error0, 1 h 16 min 48 s |
| Read after power removal | [Original fio JSON](../evidence/final-verify-065039/cx400-full.json) | Entire capacity matched, 59 min 48 s |

The recovery summary is derived from the retained private report; it is not a replacement for the original raw report. Full vendor images, raw NAND/RAM dumps and host-wide logs are not distributed here. See [evidence provenance](evidence.md).

## Full capacity and data verification

Both fio stages covered two contiguous ranges:

- Bulk: offset0, 512,109,838,336 bytes, 1 MiB blocks.
- Tail: offset512,109,838,336, 352,256 bytes, 4 KiB blocks.

The total is **512,110,190,592 bytes**, or 1,000,215,216 sectors of 512 bytes. Both jobs ended with `error=0`, `short_ios=0` and `drop_ios=0`; the tail was not lost to rounding.

The read used `fio --readonly`, `rw=read`, `verify=pattern`, `verify_interval=4096`, `do_verify=1`, and the original pattern `0x4501af406dd887f3eef3becca4e13f66`. Payload bytes were compared to that pattern. Headers included offsets and CRC32C checks every 4 KiB; this should not be described as CRC32C over every byte of the payload.

Prior checks on a regular file confirmed that fio3.39 detected both a wrong pattern and a deliberately flipped bit.

| SMART device statistic | Before read | After read | Delta |
|---|---:|---:|---:|
| Logical Sectors Read | 22,608 | 1,000,237,824 | **1,000,215,216** |
| Logical Sectors Written | 1,279,427,248 | 1,279,427,248 | **0** |

The independent read-sector delta equals the whole advertised capacity. The read phase performed no user-data write or TRIM.

## Cold power cycle

The retained write state records `Power_Cycle_Count=2`; the read ran at count3 and also checked a different kernel boot ID. The pattern/state were preserved, not regenerated for the read.

The write ended at 01:50:19 UTC+02 on 2026-10-25. The read ran from 06:50:40 to 07:50:28 UTC+01. The offset changed when daylight saving time ended that night. The measured read duration was 3,587.771 seconds, approximately **142.738 MB/s**. Average write throughput was approximately **111.135 MB/s**.

## SATA qualification

The write encountered four groups of ATA bus/ICRC/Handshk errors and four link resets at 3 Gb/s. CRC increased from4 to8. The kernel reduced the link to1.5 Gb/s; no further SATA errors appeared in the retained write log after that reduction.

During the later complete read at1.5 Gb/s:

| Observation | Result |
|---|---|
| New kernel output | None; `kernel-during.txt` is empty |
| fio / kernel-monitor stderr | Empty |
| CRC_Error_Count | 8 → 8 |
| Hardware Resets | 36 → 36 |
| Reported Uncorrectable Errors | 0 → 0 |
| Bad_Blk_Ct_Lat/Erl | 0/167 → 0/167 |
| SMART status | PASSED before and after |

Not every PHY counter was unchanged: PhyRdy→PhyNRdy transitions increased7→10 without new CRC, COMRESET or kernel errors. The cause of those transitions is unresolved. Attribute168 also reset across the cold boot; its value of0 during the read does not erase earlier errors.

The host/caddy, connection and SSD electronics have not been separated as possible causes of faster-link errors. `libata.force=4:1.5Gbps` is a Linux host-port setting, not a persistent firmware speed change or a guarantee on another computer.

## Meaning of the final warning label

`DATA_VERIFIED_WITH_KERNEL_WARNINGS` retained 69 warning lines from the earlier write, across four episodes. The current read reported:

```json
{"kernel_warnings": [], "smart_counter_changes": {}}
```

Both fio jobs and the process completed successfully. The label preserves the previous transmission problem; it does not indicate a new pattern mismatch during the cold read.

## What is established

Normal SBFM61.3 boot, full capacity and matching user data after power removal were confirmed. Original files were not recovered. Reinitialization changed model/serial and SMART metadata: a life indicator of100 and reset hours do not make the physical NAND new. Long-term reliability and operation at3/6 Gb/s have not been established.
