#!/usr/bin/env python3
import sys
import json

if len(sys.argv) != 4:
    print("Usage: 1_protection_level_digest.py old.jsonl new.jsonl output_file.json")
    sys.exit(1)

old_file, new_file, output_file = sys.argv[1], sys.argv[2], sys.argv[3]

# Base protection levels (dominant scores)
base_score = {
    "normal": 10,
    "dangerous": 20,
    "signature": 30,
    "signatureOrSystem": 30,
    "internal": 40
}

# Flag weights (minor modifiers)
flag_weights = {
    "privileged": 5,
    "appop": 2,
    "runtime": 2,
    "instant": 1,
    "development": 1,
    "verifier": 1,
    "installer": 1,
    "preinstalled": 1,
    "vendorPrivileged": 3,
    "pre23": 0.5,
    "setup": 1,
    "oem": 1,
    "systemTextClassifier": 1,
    "documenter": 1
}


def score_level(level_string):
    if not level_string:
        return base_score["normal"]  # Default to "normal" if unspecified

    parts = [p.strip() for p in level_string.split('|') if p.strip()]
    base = None
    flags = []

    for part in parts:
        if part in base_score and base is None:
            base = part
        else:
            flags.append(part)

    base_val = base_score.get(base, base_score["normal"])
    flag_val = sum(flag_weights.get(f, 1) for f in flags)

    return base_val + flag_val


def load_jsonl(filepath):
    result = {}
    with open(filepath) as f:
        for line in f:
            entry = json.loads(line)
            result[entry["permission_name"]] = entry["protection_level"]
    return result


old = load_jsonl(old_file)
new = load_jsonl(new_file)

summary = {
    "increased": [],
    "decreased": [],
    "added": [],
    "removed": []
}

# Compare overlapping permissions
for perm, old_level in old.items():
    if perm in new:
        new_level = new[perm]
        old_score = score_level(old_level)
        new_score = score_level(new_level)

        if new_score > old_score:
            print(f"[INCREASED] {perm}: {old_level} → {new_level}")
            summary["increased"].append({
                "permission_name": perm,
                "old_level": old_level,
                "new_level": new_level
            })
        elif new_score < old_score:
            print(f"[DECREASED] {perm}: {old_level} → {new_level}")
            summary["decreased"].append({
                "permission_name": perm,
                "old_level": old_level,
                "new_level": new_level
            })

# Detect removed permissions
for perm in old:
    if perm not in new:
        summary["removed"].append({
            "permission_name": perm,
            "old_level": old[perm]
        })
        print(f"[REMOVED] {perm}")

# Detect newly added permissions
for perm in new:
    if perm not in old:
        summary["added"].append({
            "permission_name": perm,
            "new_level": new[perm]
        })
        print(f"[ADDED] {perm}: {new[perm]}")

# Write to output file
with open(output_file, "w") as f:
    json.dump(summary, f, indent=2)

print("\nSummary written to", output_file)
