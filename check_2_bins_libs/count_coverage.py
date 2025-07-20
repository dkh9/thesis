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

def is_fully_identical(entry):
    return entry.get("Identical Functions") == entry.get("Total Functions Analyzed")

def count_bin_and_lib_json_entries(bin_json_path: Path):
    with open(bin_json_path) as f:
        data = json.load(f)
        total_bin_count = 0
        total_lib_count = 0

        bin_count = 0
        lib_count = 0
        tee_count = 0
        rc_bin_count = 0
        rc_lib_count = 0
        hardening_diff_count = 0

        for key, entry in data.items():
            is_lib = key.endswith(".so")

            if is_lib:
                total_lib_count += 1
            else:
                total_bin_count += 1

            if is_fully_identical(entry):
                continue  # skip fully identical entries from further stats

            if is_lib:
                lib_count += 1
                if entry.get("Mentioned in .rc"):
                    rc_lib_count += 1
            else:
                bin_count += 1
                if entry.get("TEE"):
                    tee_count += 1
                if entry.get("Mentioned in .rc"):
                    rc_bin_count += 1

            if entry.get("Hardening comparison", {}).get("identical") is False:
                hardening_diff_count += 1

        return (
            bin_count, lib_count,
            tee_count, rc_bin_count, rc_lib_count, hardening_diff_count,
            total_bin_count, total_lib_count
        )

def show_stats(name, json_count, actual_count):
    pct = (json_count / actual_count * 100) if actual_count > 0 else 0
    print(f"{name}:")
    print(f"  In firmware: {actual_count}")
    print(f"  In JSON (excluding identical): {json_count}")
    print(f"  Coverage:    {pct:.2f}% ({json_count}/{actual_count})\n")

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
    (
        bin_json_count, lib_json_count,
        tee_count, rc_bin_count, rc_lib_count, hardening_diff_count,
        total_bin_json_count, total_lib_json_count
    ) = count_bin_and_lib_json_entries(bin_json_path)

    show_stats("ELF Binaries (non-.so)", bin_json_count, actual_bin_count)
    show_stats("Shared Libraries (.so)", lib_json_count, actual_lib_count)

    # Additional stats
    print("Additional binary and library stats from JSON (excluding identical):")
    print(f"  Binaries with TEE:                     {tee_count}")
    print(f"  Binaries with 'Mentioned in .rc':      {rc_bin_count}")
    print(f"  Libraries with 'Mentioned in .rc':     {rc_lib_count}")
    print(f"  Entries with non-identical hardening:  {hardening_diff_count}")
    print()
    print("Total JSON entries including identical:")
    print(f"  Total binaries in JSON:                {total_bin_json_count}")
    print(f"  Total libraries in JSON:               {total_lib_json_count}")

if __name__ == "__main__":
    main()
