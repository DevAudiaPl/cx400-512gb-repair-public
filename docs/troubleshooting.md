# Failed attempts and their interpretation

| Observation | Finding | Practical implication |
|---|---|---|
| USB PS3111/0 MB, failed reader IOCTLs | Bridges differed in vendor-command support; native SATA exposed all CE IDs | USB failure alone does not establish NAND failure |
| VIA/JM20329 bridges | Using JM20329 did not make every tool detect the SSD consistently | A bridge chipset name is not a compatibility guarantee |
| Dell USB boot disappeared or stalled | The connected failed SSD affected that boot configuration | The successful host was the Lenovo optical-bay setup; UEFI was not a demonstrated repair requirement |
| Empty MPTool tiles | “Current Setting” described a configured profile | A default256 GB profile/other FID was not device identification |
| MPTool detected correct FID but failed | NAND selection alone did not initialize the SSD | Preserve the operation's report, not just a detection screenshot |
| Updater success followed by ROM mode | API success did not prove durable installed firmware | Require NAND readback and a cold normal boot |
| repairS11 ReadInfoBlock/status51 | The command was rejected in that controller state | Assess status, error register and operation together |
| Section_0 CRC failure | Programming had not completed correctly | Do not guess another image from its version string |
| Windows seed failure after PreFormat | Initialization/programming remained incomplete, including attempts over SATA | Not every failure was a USB transport problem |
| Linux v1 Erase09 rejection | Wrong LBA Low00 for the receiver | Corrected to88 based on receiver/host code analysis |
| Linux v2 recovery | Corrected erase, complete programming and matching NAND readback | This is the successful documented sequence |
| fio v1 JSON parse failure | Expected failure text preceded JSON | Parser bug; the full SSD write had not started |
| Ctrl+C during data test | Stopped fio, not firmware programming | Preserve state; incomplete write cannot become completed proof |
| `libata=4:3.0Gbps` | Wrong parameter name | Correct syntax uses `libata.force` |
| `libata.force=4:3.0 Gbps` | Extra token; abbreviated3.0 was accepted and SMART confirmed3 Gb/s | Real bus errors cannot be dismissed as only a spacing mistake |
| Z565 soft lockup | Available log lacked the actual lockup stack; IRQ/atl1c watchdog messages were present | `pci=nomsi` remained a workaround, not a proven cause diagnosis |
| Final full write | Completed after kernel reduced SATA speed | Historical faster-link warnings remain relevant |
| Full cold read | Every byte matched; no new CRC/reset/kernel errors | Confirmed user-data operation under the measured conditions |

## An interrupted data test

Ctrl+C during fio is not itself a reason to reflash firmware. An interrupted state such as `WRITE_IN_PROGRESS` does not prove full coverage and must not be accepted by a completed-write verifier.

In this case a confirmed manual interruption was preserved and one new full write was started after all previous processes ended. This is not permission to clear guards after an unexplained I/O error. A completed write should proceed to power removal and read verification.

## Expected negative fio checks

`sanity-wrong-pattern-EXPECTED` and `sanity-corruption-EXPECTED` deliberately produce EILSEQ/error84 on a small regular file. An unrelated EIO, a short transfer or a truncated report is not an accepted negative test.

Real fio3.39 output contained `fio: pid=..., err=84/...` lines before JSON. The corrected parser separates the prefix from a single complete JSON document while still checking process/job errors.

## Progress output

An old `fio_wait` record only means the child process has not exited. v3 reports read bytes from kernel statistics; v4 adds percentage and ETA. Completed content verification is established by the final fio result, not elapsed time or an I/O counter reaching100%.
