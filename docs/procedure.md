# Recovery procedure

This procedure describes the successful configuration in the [README](../README.md). For another SSD, read [Adapting the code](adapting.md) first. This is destructive initialization, not file recovery.

## 1. Identify the hardware

Confirm the PS3111 controller, original SBFM61.3 firmware family, eight CE indices `0–3, 8–11` and full NAND ID `98 3e 99 b3 7a 72 08 06`. The [historical Flash ID output](../evidence/hardware/phison-flash-id.txt) is an identification reference, not evidence that all NAND blocks are healthy.

Matching capacity or product branding is insufficient. A different NAND ID, geometry, controller revision or firmware image requires separate analysis.

## 2. Establish native SATA and Linux boot

The successful host was a Lenovo Z565 with the SSD in an optical-bay SATA caddy, AHCI enabled, and no jumper held during the successful run. Do not infer jumper positions for other PCBs from this case.

The preserved recovery code expects `ata4/link4` and a measured **1.5 Gb/s** link. Determine the actual target's sysfs path before adapting this configuration. Port numbers belong to the host, not the SSD.

For the documented host, the Linux kernel command line was:

```text
pci=nomsi libata.force=4:1.5Gbps
```

`1.5Gbps` is one token. Replace an old `libata.force` setting rather than appending conflicting settings. A one-time GRUB edit applies only to that boot.

```sh
cat /proc/cmdline
lsblk -bdo NAME,SIZE,MODEL,SERIAL,TRAN
```

`pci=nomsi` was a workaround after a host soft lockup. The captured log did not prove MSI was its cause. Applying it to a different machine requires a separate reason.

## 3. Prepare a persistent working directory

Use 64-bit Linux with Python 3, native SG_IO, sysfs and the required debugfs/tracefs/libata tracing support. Debian Trixie's Python 3.13 also supports the asset-preparation dependency. fio and smartmontools are required for the later data tests.

```sh
sudo apt-get install python3 fio smartmontools
sudo modprobe sg
```

Complete [asset preparation](assets.md) on a healthy filesystem. Logs and state must survive reboots and power removal. Keep them off the SSD being repaired and outside ephemeral live-system storage.

The prepared directory `work/recovery-v2` contains the unchanged recovery code, checked local assets and offline tests:

```sh
cd work/recovery-v2
python3 -B offline_test.py
```

Expect **236 offline checks**. These checks exercise mock transports and content guards; they do not establish hardware compatibility.

## 4. Run the repair on the confirmed target

Only after hardware matching and acceptance of complete data loss:

```sh
sudo python3 cx400-recover.py --repair
```

The default command without `--repair` performs prechecks that can load the burner into RAM and unlock VUC commands. It does not perform the erase/PreFormat/program sequence, but it has active effects on the controller.

The complete workflow:

1. Identifies ROM `PS3111 / SBRM02.0` or the expected already running burner.
2. Loads and verifies SBBQ61L3 in IRAM/SRAM.
3. Unlocks VUC and checks all CE IDs and known RAM control words.
4. If initialization is missing, performs Erase09 with Low88, Erase05 and PreFormat. An existing valid InfoBlock may be reused in the required state.
5. Sends the normal firmware seed (`0x80`), checks the section table/key, and sends code (`0x82`).
6. Verifies every staged SRAM section before commit (`0x41`).
7. Reads the header and entire 770,048-byte programmed code back from NAND (`0x31`) and compares contents.

Any transport, trace, device-state or content failure stops the workflow without automatic retry/reset. A waiting message is not proof of progress: the original limits are 960 seconds per erase operation and 1,280 seconds for PreFormat. Preserve the result ZIP and current power state for diagnosis after failure.

## 5. Require readback success, then remove power

The required programming result is:

```text
PROGRAMMED_AND_VERIFIED_POWER_CYCLE_REQUIRED
```

This confirms programming and code readback. Normal boot and user-data retention still need testing.

```sh
sudo poweroff
```

With the computer off, remove SSD power for at least 30 seconds and reconnect. Boot Linux with the reviewed link configuration. Check model, firmware, full capacity and the newly assigned serial; device letters can change.

## 6. Test the complete user area

The required sequence is **full write → power removal → full verified read of the same pattern**. SMART PASSED or detection of 512 GB alone is insufficient.

Prepare a separate working copy of `scripts/final-test-v2` using [the adaptation instructions](adapting.md). The historical original has this drive's serial and a guard rejecting a forced 1.5 Gb/s limit. Review that guard before any new test on a link that requires 1.5 Gb/s.

The reviewed copy uses:

```sh
sudo python3 cx400-test.py write
```

After `WRITE_COMPLETE_POWER_CYCLE_REQUIRED`, power off, physically remove SSD power, reboot, and use the same persistent directory/state:

```sh
sudo python3 cx400-test.py verify
```

Preserve `test-state.json`: it binds the pattern, completed write and power-cycle evidence. The test covers 512,109,838,336 bytes in 1 MiB blocks plus a 352,256-byte tail in 4 KiB blocks.

The included v3/v4 scripts are read-only historical verifiers bound to the original write report, source hash and serial. v3 performed the successful cold read; v4 only adds display/ETA changes and was checked offline. They are not drop-in verifiers for a new write.

## 7. Assess the result

Check both fio jobs, exact byte counts, process/job errors, matching pattern, cold power cycle, current kernel messages and changes in CRC/reset/uncorrectable counters. A completed I/O counter alone does not prove content verification.

The historical `DATA_VERIFIED_WITH_KERNEL_WARNINGS` retained warnings from the previous write. Its current read had no new kernel errors. See [Results](results.md) for the distinction and remaining SATA limitation.

The repaired SSD has already completed these stages. Partitioning and filesystem creation are subsequent use, not reasons to repeat firmware initialization.
