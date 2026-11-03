#!/usr/bin/env python3
"""Run the actual offset selector against its pre-change baseline on the host."""
import argparse
from pathlib import Path
import re
import struct
import subprocess
import tempfile

BASE = "2f7033f4185d3062a504e83ac75f6b4e2570dafb"
ROOT = Path(__file__).resolve().parents[1]


def selector(source):
    start = source.index("int set_offsets(void) {")
    pos = source.index("{", start)
    depth = 1
    end = pos + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def baseline_file(commit, path):
    return subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=ROOT, text=True)


def build_harness(folder, files):
    folder.mkdir()
    (folder / "offsets.h").write_text(files["include/offsets.h"])
    (folder / "offsets.c").write_text(files["source/offsets.c"])
    code = '''#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "offsets.h"
offset_list env_offset;
uint32_t fw;
static uint32_t test_raw, test_soc;
uint32_t kernel_get_fw_version(void) { return test_raw; }
int sceKernelGetMainSocId(void) { return (int)test_soc; }
void notify(const char *format, ...) { (void)format; }
'''
    code += selector(files["source/utils.c"])
    code += '''
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  test_raw = (uint32_t)strtoul(argv[1], NULL, 0);
  test_soc = (uint32_t)strtoul(argv[2], NULL, 0);
  int32_t result = set_offsets();
  fwrite(&result, sizeof(result), 1, stdout);
  fwrite(&fw, sizeof(fw), 1, stdout);
  fwrite(&env_offset, sizeof(env_offset), 1, stdout);
  return 0;
}
'''
    (folder / "harness.c").write_text(code)
    executable = folder / "harness"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    str(folder / "harness.c"), str(folder / "offsets.c"),
                    "-o", str(executable)], check=True)
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=BASE)
    args = parser.parse_args()
    paths = ("include/offsets.h", "source/offsets.c", "source/utils.c")
    old = {p: baseline_file(args.baseline, p) for p in paths}
    new = {p: (ROOT / p).read_text() for p in paths}
    assert new["include/offsets.h"] == old["include/offsets.h"]
    fields = re.findall(r"uint64_t\s+(\w+)\s*;", new["include/offsets.h"])
    gpu_index = fields.index("PS5_PRO_GPU_FW_OFFSET")
    assert len(fields) == 61

    function = selector(old["source/utils.c"])
    matches = list(re.finditer(r"case (0x[0-9a-fA-F]+):", function))
    cases = {0, 0x99990000}
    for index, match in enumerate(matches):
        version = int(match[1], 16)
        block = function[match.end():matches[index+1].start() if index+1 < len(matches) else len(function)]
        exact = re.search(r"kernel_get_fw_version\(\) != (0x[0-9a-fA-F]+)U", block)
        raw = int(exact[1], 16) if exact else version << 16
        cases.add(raw)
        if exact:
            cases.add(raw ^ 1)  # preserve retail build rejection as well

    count = 0
    changed = 0
    with tempfile.TemporaryDirectory() as temporary:
        base_exe = build_harness(Path(temporary) / "baseline", old)
        new_exe = build_harness(Path(temporary) / "patched", new)
        for raw in sorted(cases):
            for soc in (0, 0x840FD0):
                before = subprocess.check_output([str(base_exe), hex(raw), hex(soc)])
                after = subprocess.check_output([str(new_exe), hex(raw), hex(soc)])
                assert len(before) == len(after) == 8 + 61 * 8
                if raw == 0x12400009 and soc == 0x840FD0:
                    assert struct.unpack_from("<i", before)[0] == 0
                    offset = 8 + gpu_index * 8
                    assert struct.unpack_from("<Q", before, offset)[0] == 0
                    assert struct.unpack_from("<Q", after, offset)[0] == 0x1B1E108
                    expected = bytearray(before)
                    struct.pack_into("<Q", expected, offset, 0x1B1E108)
                    assert after == bytes(expected), "Another offset changed on 12.40 Pro"
                    changed += 1
                else:
                    assert before == after, f"Behavior changed: firmware={raw:#x}, SoC={soc:#x}"
                count += 1
    assert changed == 1
    print(f"PASS: {count} selector cases; only retail 12.40 Pro enables the new GPU offset")


if __name__ == "__main__":
    main()
