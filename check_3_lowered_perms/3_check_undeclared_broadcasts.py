#!/usr/bin/env python3
import sys
import json
from collections import defaultdict

def parse_broadcasts(path):
    """Returns a set of all protected broadcasts, ignoring lines starting with '###'."""
    broadcasts = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("###") and line:
                broadcasts.add(line)
    return broadcasts

def parse_intents(path):
    """Returns a set of all intent actions, ignoring lines starting with '=='."""
    intents = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("==") and line:
                intents.add(line)
    return intents

def main():
    if len(sys.argv) != 6:
        print("Usage: 3_check_undeclared_broadcasts.py <protected_broadcasts_v1.txt> <intent_filters_v1.txt> <protected_broadcasts_v2.txt> <intent_filters_v2.txt> <outfile>")
        sys.exit(1)

    protected_path_1, intents_path_1, protected_path_2, intents_path_2, outfile = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]

    protected_v1 = parse_broadcasts(protected_path_1)
    intents_v1 = parse_intents(intents_path_1)

    protected_v2 = parse_broadcasts(protected_path_2)
    intents_v2 = parse_intents(intents_path_2)

    decreased_security = []
    increased_security = []

    # Broadcasts declared in v1 but missing in v2 (potential security regression)
    removed_broadcasts = protected_v1 - protected_v2
    print("REMOVED: ", removed_broadcasts)
    for bc in removed_broadcasts:
        if bc in intents_v2:
            decreased_security.append(bc)

    # Broadcasts declared in v2 but missing in v1 (potential security improvement)
    added_broadcasts = protected_v2 - protected_v1
    print("ADDED:", added_broadcasts)
    for bc in added_broadcasts:
        if bc in intents_v1:
            increased_security.append(bc)
    
    print("Length protected_v1:", len(protected_v1))
    print("Length protected_v2:", len(protected_v2))

    output = {
        "decreased": decreased_security,
        "increased": increased_security
    }

    #print(json.dumps(output, indent=2))
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2)
    
    print("Summary written to ", outfile)
    
if __name__ == "__main__":
    main()
