#!/usr/bin/env python3

import sys
import json
import re

def extract_paths_from_file(path):
    path_set = set()
    pattern = re.compile(r"^\d+:\s*(.+->.+)$")
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            match = pattern.match(line)
            if match:
                cleaned_path = match.group(1).strip()
                path_set.add(cleaned_path)
    return path_set

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <file1.txt> <file2.txt> <outfile>")
        sys.exit(1)

    file1, file2, outfile = sys.argv[1], sys.argv[2], sys.argv[3]

    set1 = extract_paths_from_file(file1)
    set2 = extract_paths_from_file(file2)
    print(f"Set 1 size: {len(set1)}, set 2 size: {len(set2)}")

    result = {
        "left": sorted(set1 - set2),
        "right": sorted(set2 - set1)
    }

    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)

if __name__ == "__main__":
    main()
