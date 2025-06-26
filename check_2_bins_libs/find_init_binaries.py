import os
import re
from pathlib import Path

def resolve_binary_path(binary, partition_root):
    """
    Given a binary path like /system/bin/foo and the root dir (e.g., a15-850),
    return actual file path on disk.
    """
    path = binary.lstrip("/")  # remove leading slash
    first_part = path.split("/")[0]

    # Handle partition prefixes
    if first_part in ("vendor", "product", "odm", "system_ext"):
        subpath = "/".join(path.split("/")[1:])  # strip the leading system/, etc.
        actual_path = partition_root / first_part / subpath
    else:
        # fallback for binaries that don’t have a partition prefix
        actual_path = partition_root / first_part / path

    return actual_path

def collect_rc_files(rc_root):
    return list(Path(rc_root).rglob("*.rc"))

def parse_rc_file(path, service_map, found_binaries):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("service "):
                match = re.match(r"service\s+(\S+)\s+(\S+)", line)
                if match:
                    service_name, binary_path = match.groups()
                    service_map[service_name] = binary_path
                    found_binaries.add(binary_path)

            elif line.startswith("exec") or line.startswith("exec_background"):
                parts = line.split()
                for i, token in enumerate(parts):
                    if token.startswith("/") and not token.startswith("/dev"):  # crude heuristic
                        found_binaries.add(token)
                        break

            elif line.startswith("exec_start "):
                match = re.match(r"exec_start\s+(\S+)", line)
                if match:
                    svc = match.group(1)
                    if svc in service_map:
                        found_binaries.add(service_map[svc])

def is_elf_binary(path):
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except Exception:
        return False


def main(rc_dir):
    rc_dir = Path(rc_dir).resolve()
    print("RC_DIR: ", rc_dir)
    #system_root = rc_dir.parents[1]  # Assuming rc_dir = /path/to/system/etc/init → system_root = /path/to/system

    service_map = {}
    found_binaries = set()

    rc_files = collect_rc_files(rc_dir)
    print("RC FILES LIST:")
    for rc_file in rc_files:
        print(rc_file)
        parse_rc_file(rc_file, service_map, found_binaries)

    print("-------------")

    filtered = []
    for binary in found_binaries:
        #rel_path = binary.lstrip("/")  # Remove leading slash
        #actual_path = rc_dir / rel_path
        actual_path = resolve_binary_path(binary, rc_dir)
        print("Actual path: ", actual_path, " result: ", is_elf_binary(actual_path))
        if is_elf_binary(actual_path):
            filtered.append(actual_path)

    print(f"\nUsed ELF binaries in .rc files ({len(filtered)}):")
    with open(args.out_file, "w") as f:
        for bin_path in sorted(filtered):
            print(f"  {bin_path}")
            f.write(str(bin_path)+ "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract /system/bin/* binaries used during Android init")
    parser.add_argument("rc_dir", help="Directory containing .rc files (e.g., extracted system/etc/init/)")
    parser.add_argument("out_file", help="Output file")
    args = parser.parse_args()
    main(args.rc_dir)
