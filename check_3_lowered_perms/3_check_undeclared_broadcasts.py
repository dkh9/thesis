#!/usr/bin/env python3
import sys
import json
from collections import defaultdict

def parse_broadcasts(path):
    """Parses protected broadcasts script output"""
    result = {}
    current_apk = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("###"):
                current_apk = line[4:]
                result[current_apk] = []
            elif current_apk and line:
                result[current_apk].append(line)
    return result

def parse_intents(path):
    """Parses intent-filters script output"""
    result = {}
    current_apk = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("=="):
                current_apk = line[3:-2] if line.endswith("==") else line[3:]
                result[current_apk] = []
            elif current_apk and line:
                result[current_apk].append(line)
    return result

def main():
    if len(sys.argv) != 3:
        print("Usage: check_undeclared_broadcasts.py <protected_broadcasts.txt> <intent_filters.txt>")
        sys.exit(1)

    protected_path, intents_path = sys.argv[1], sys.argv[2]

    protected = parse_broadcasts(protected_path)
    intents = parse_intents(intents_path)

    all_declared = set()
    for plist in protected.values():
        all_declared.update(plist)

    summary = defaultdict(list)
    for apk, intent_list in intents.items():
        for intent in intent_list:
            if intent not in all_declared:
                summary[apk].append(intent)

    with open("undeclared_broadcasts_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("Summary written to undeclared_broadcasts_summary.json")

if __name__ == "__main__":
    main()
