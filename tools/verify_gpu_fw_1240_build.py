#!/usr/bin/env python3
"""Compare compiled offset tables and kernel/HV blobs against the base build."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tables(path):
    data = path.read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01"
    offset = struct.unpack_from("<Q", data, 40)[0]
    stride, count = struct.unpack_from("<HH", data, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset+i*stride) for i in range(count)]
    result = {}
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        string_section = sections[section[6]]
        strings = data[string_section[4]:string_section[4]+string_section[5]]
        for pos in range(section[4], section[4]+section[5], section[9]):
            name_off, _, _, index, address, size = struct.unpack_from("<IBBHQQ", data, pos)
            name = strings[name_off:strings.index(b"\0", name_off)].decode()
            if not re.fullmatch(r"off_[0-9a-fA-F]{4}", name):
                continue
            assert size == 488, (name, size)
            owner = sections[index]
            file_offset = owner[4] + address - owner[3]
            result[name] = data[file_offset:file_offset+size]
    assert "off_1240" in result
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("patched", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    before = tables(args.baseline / "bin/ps5-linux-loader.elf")
    after = tables(args.patched / "bin/ps5-linux-loader.elf")
    assert before.keys() == after.keys()
    for name, original in before.items():
        expected = bytearray(original)
        if name == "off_1240":
            assert struct.unpack_from("<Q", original, 39*8)[0] == 0
            struct.pack_into("<Q", expected, 39*8, 0x1B1E108)
        assert bytes(expected) == after[name], f"Unexpected compiled offset change in {name}"

    old_blobs = {p.relative_to(args.baseline): p for p in args.baseline.glob("shellcode_*/*.bin")}
    new_blobs = {p.relative_to(args.patched): p for p in args.patched.glob("shellcode_*/*.bin")}
    assert old_blobs.keys() == new_blobs.keys() and len(old_blobs) >= 7
    blob_hashes = {}
    for path in old_blobs:
        original = old_blobs[path].read_bytes()
        assert original == new_blobs[path].read_bytes(), f"Shellcode changed: {path}"
        blob_hashes[str(path)] = sha(original)

    elf = (args.patched / "bin/ps5-linux-loader.elf").read_bytes()
    report = {
        "offset_tables_compared": len(before),
        "only_table_change": "off_1240.PS5_PRO_GPU_FW_OFFSET: 0 -> 0x1B1E108",
        "all_kernel_hv_blobs_byte_identical": True,
        "shellcode_sha256": blob_hashes,
        "elf_size": len(elf), "elf_sha256": sha(elf),
        "new_loader_boot_tested": False,
        "note": "Live source firmware capture was validated separately; this new loader still requires a console boot test."
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
