import json

# Load JSON
with open("../shiba-oct-nov-23-apks.json") as f:
    data = json.load(f)

filtered_entries = {
    k: v for k, v in data.items() if "error" not in v
}

tier1_entries = []
non_tier1_entries = []

for k, v in filtered_entries.items():
    changes = v.get("changes", {})
    tier_1 = changes.get("tier_1", [])
    tier_2 = changes.get("tier_2", [])

    if tier_1:
        tier1_entries.append((k, v, len(tier_1)))
    else:
        non_tier1_entries.append((k, v, len(tier_2)))

# Sort both lists by count descending
tier1_entries.sort(key=lambda x: -x[2])
non_tier1_entries.sort(key=lambda x: -x[2])

# Reassemble into ordered dict
sorted_result = {k: v for k, v, _ in tier1_entries + non_tier1_entries}

# Output to JSON
with open("sorted_apk_diffs.json", "w") as f:
    json.dump(sorted_result, f, indent=2)

print("Sorted output written to sorted_apk_diffs.json")
