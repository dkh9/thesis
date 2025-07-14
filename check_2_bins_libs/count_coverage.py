#!/usr/bin/env python3
import sys
import json
from pathlib import Path

def count_apks(firmware_path: Path) -> int:
    return len(list(firmware_path.rglob("*.apk")))

def count_bins_and_libs(firmware_path: Path):
    binaries = []
    libraries = []
    for f in firmware_path.rglob("*"):
        if f.is_file() and f.suffix == "":
            try:
                with open(f, 'rb') as fp:
                    magic = fp.read(4)
                    if magic == b'\x7fELF':
                        binaries.append(f)
            except Exception:
                continue
        elif f.suffix == ".so":
            try:
                with open(f, 'rb') as fp:
                    magic = fp.read(4)
                    if magic == b'\x7fELF':
                        libraries.append(f)
            except Exception:
                continue
    return len(binaries), len(libraries)

def count_apk_json_entries(apk_json_path: Path) -> int:
    with open(apk_json_path) as f:
        data = json.load(f)
        return len(data)

def count_bin_and_lib_json_entries(bin_json_path: Path):
    with open(bin_json_path) as f:
        data = json.load(f)
        bin_count = 0
        lib_count = 0
        for key in data:
            if key.endswith(".so"):
                lib_count += 1
            else:
                bin_count += 1
        return bin_count, lib_count

def show_stats(name, json_count, actual_count):
    pct = (json_count / actual_count * 100) if actual_count > 0 else 0
    print(f"{name}:")
    print(f"  In firmware: {actual_count}")
    print(f"  In JSON:     {json_count}")
    print(f"  Coverage:    {json_count / actual_count:.2%} ({json_count}/{actual_count})\n")

def main():
    if len(sys.argv) != 4:
        print("Usage: script.py <firmware_path> <apk_sorted.json> <bin_sorted.json>")
        sys.exit(1)

    firmware_path = Path(sys.argv[1])
    apk_json_path = Path(sys.argv[2])
    bin_json_path = Path(sys.argv[3])

    # APKs
    actual_apk_count = count_apks(firmware_path)
    apk_json_count = count_apk_json_entries(apk_json_path)
    show_stats("APK", apk_json_count, actual_apk_count)

    # Binaries and shared libraries
    actual_bin_count, actual_lib_count = count_bins_and_libs(firmware_path)
    bin_json_count, lib_json_count = count_bin_and_lib_json_entries(bin_json_path)
    show_stats("ELF Binaries (non-.so)", bin_json_count, actual_bin_count)
    show_stats("Shared Libraries (.so)", lib_json_count, actual_lib_count)

if __name__ == "__main__":
    main()
