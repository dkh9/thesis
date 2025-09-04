#!/usr/bin/env python3
import json
import sys

if len(sys.argv) != 3:
    print("Usage: apk_priority.py <input_json> <output_json>")
    sys.exit(1)

input_path = sys.argv[1]
output_path = sys.argv[2]

# Load JSON
with open(input_path) as f:
    data = json.load(f)

filtered_entries = {
    k: v for k, v in data.items() if "error" not in v
}

tier1_entries = []
non_tier1_entries = []
total_count = 0

for k, v in filtered_entries.items():
    changes = v.get("changes", {})
    tier_1 = changes.get("tier_1", [])
    tier_2 = changes.get("tier_2", [])

    if tier_1:
        tier1_entries.append((k, v, len(tier_1)))
    else:
        non_tier1_entries.append((k, v, len(tier_2)))
    total_count += 1

# Sort both lists by count descending
tier1_entries.sort(key=lambda x: -x[2])
non_tier1_entries.sort(key=lambda x: -x[2])

# Reassemble into ordered dict
sorted_result = {k: v for k, v, _ in tier1_entries + non_tier1_entries}

# Output to JSON
with open(output_path, "w") as f:
    json.dump(sorted_result, f, indent=2)

print(f"Sorted output written to {output_path}")
print("With tier_1 entries: ", len(tier1_entries))
print("Total: ", total_count)
