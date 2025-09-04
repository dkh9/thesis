import subprocess
from collections import defaultdict
import json

def get_needed_libs(binary_path):
    try:
        result = subprocess.run(
            ["readelf", "-d", binary_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True,
        )
    except Exception as e:
        print(f"Error reading {binary_path}: {e}")
        return []

    needed_libs = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if "(NEEDED)" in line:
            # Example line:
            # 0x0000000000000001 (NEEDED)             Shared library: [liblog.so]
            start = line.find('[')
            end = line.find(']')
            if start != -1 and end != -1 and end > start:
                libname = line[start+1:end]
                needed_libs.append(libname)
    return needed_libs

def main(binaries_file):
    lib_to_bins = defaultdict(list)

    with open(binaries_file, "r") as f:
        for line in f:
            binary_path = line.strip()
            if not binary_path:
                continue

            libs = get_needed_libs(binary_path)
            for lib in libs:
                lib_to_bins[lib].append(binary_path)

    print(json.dumps(lib_to_bins, indent=2))

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} binaries_list.txt")
        sys.exit(1)

    main(sys.argv[1])
