# PS5 Pro 12.40 GPU firmware extraction

This fork adds the GPU firmware table offset measured on a retail PS5 Pro
running system software **12.40 (`0x12400009`)**, SoC **`0x840fd0`**:

```c
.PS5_PRO_GPU_FW_OFFSET = 0x1B1E108,
```

The value is relative to the runtime kernel text base. On this firmware it
is also `kernel_data_base + 0x0DCE108`; it is not an absolute kernel address.
Other loader offsets and the GPU firmware reconstruction code are unchanged.

The source shares `off_1240` with 12.20. The selected GPU offset is explicitly
cleared for 12.20 and for non-Pro 12.40 hardware, so the new extraction path is
enabled only for the verified retail 12.40 Pro combination. Existing retail
build checks remain in place; other firmware families retain their behavior.

## Evidence and limits

A separate diagnostic payload captured a bounded 64 KiB kernel-data window
and then the eight headers, tag strings and payloads. Both captures were made
during the same boot. Exactly one aligned eight-pointer sequence in that
window matched the candidate. Header fields, feature sequence, lengths,
jump-table bounds, RLC XOR and both SDMA sums checked out. The PFP payload
contained the original guarded bytes `63 00 c0 96` at payload offset `0x16B8`.

Reconstructing all eight files using the existing loader format and guarded
PFP patch produced the same SHA-256 hashes as the files previously measured
in that console's Linux installation. This is evidence against a corrupted
dump. It does not prove that the Viola driver path is stable in games.

**The new loader is untested on retail Pro hardware.** Only the diagnostic
capture has run on that console. A cold-boot repeat, loader boot test and GPU,
display, USB, Wi-Fi, Bluetooth, Ethernet and audio checks are still pending.
The CP firmware checksum algorithm remains unverified. No kernel dump or
proprietary firmware payload is included in this repository or build artifact.

## When the dump happens

After finding and reading the Linux boot files, `fetch_linux()` calls
`dump_device_firmwares()`. When the selected GPU offset is nonzero, the existing
code reconstructs all eight GPU files under `lib/firmware/amdgpu/`, relative
to the directory containing `initrd.img`. It opens each output with
`O_WRONLY | O_CREAT | O_TRUNC`: existing files are overwritten each time this
stage runs. A dump error is reported, but the upstream loader continues.

This loader reads `initrd.img` into memory **before** dumping the firmware.
Writing new files alongside it does not replace the firmware already packed
inside that initrd. A distribution-specific staging step must incorporate the
files. On the tested Bazzite installation, `ps5-stage-viola-fw.service` prepares
them for a subsequent Linux boot. Check the staged initrd before attributing a
change in game behavior to a fresh dump.

The boot option `amdgpu.ps5_viola_fw=0` disables the Viola path in the patched
Bazzite driver even if the loader extracts those files. This source change
does not modify that boot option or remove the fallback firmware.

## Build verification

The fork's Actions workflow builds the pinned upstream baseline and this
change with SDK v0.45. It executes the actual C offset selector on the host for
supported firmware/model combinations, compares every compiled offset table,
and checks that all generated kernel/HV shellcode blobs remain byte-identical.
The artifact contains its source commit, compiler version and ELF SHA-256.
These checks do not replace a hardware boot test.

Based on [soniciso1/ps5-linux-loader](https://github.com/soniciso1/ps5-linux-loader)
and the original work of TheOfficialFloW and its contributors. This is a
targeted experimental fork, not an upstream release.
